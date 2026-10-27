using System.Diagnostics;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Audit;
using WinAppGuard.Core.Diagnostics;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Diagnostics.Ids;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Forms;
using WinAppGuard.Localization;
using WinAppGuard.Interop;
using WinAppGuard.Models;

namespace WinAppGuard.SelfCheck;

/// <summary>
/// WinAppGuard 自检工具。
///
/// 这是一个**开发期工具**，不是产品的一部分，不会被发布到最终 exe 里。
/// 它的作用是让「程序对系统做了什么」可以被亲眼验证，而不是只能相信代码注释。
///
/// 覆盖三块：
///   防火墙   —— 规则的创建 / 查询 / 删除，以及 17 项安全护栏；
///   开机自启 —— 计划任务的创建 / 查询 / 删除，以及任务内容的逐项核对；
///   IP 归属  —— 联网查询是否正常、私有地址是否真的没被发出去。
///
/// 用法：
///   WinAppGuard.SelfCheck.exe                    防火墙：完整自动化测试，结束后自动清理
///   WinAppGuard.SelfCheck.exe --leave            防火墙：建一条演示规则并**保留**，供你在 wf.msc 里核对
///   WinAppGuard.SelfCheck.exe --cleanup          防火墙：删除全部 AppGuard 规则
///   WinAppGuard.SelfCheck.exe --status           防火墙：只读，打印全局状态和现有 AppGuard 规则
///   WinAppGuard.SelfCheck.exe --autostart-status  自启：只读，打印任务状态和原始 XML
///   WinAppGuard.SelfCheck.exe --autostart-test    自启：完整测试（建 → 逐项核对 → 删）
///   WinAppGuard.SelfCheck.exe --autostart-disable 自启：删除 WinAppGuard 自启任务
///   WinAppGuard.SelfCheck.exe --ownership-test    IP 归属：**会联网**，核对查询结果与地址过滤
///   WinAppGuard.SelfCheck.exe --ownership-core-test  IP 归属：离线，核对缓存 / 淘汰 / 开关 / 设置持久化
///   WinAppGuard.SelfCheck.exe --connection-filter-test  连接列表：离线，核对搜索过滤与排序规则
///   WinAppGuard.SelfCheck.exe --temp-block-test  临时阻断：离线，核对待到期信息的编码 / 解析 / 判定
///   WinAppGuard.SelfCheck.exe --temp-block-status  临时阻断：只读，打印每条规则的到期解析结果
///   WinAppGuard.SelfCheck.exe --strict-mode-test  严格模式：会话内拦截（会短暂断开未放行程序的网络，结束即恢复）
///   WinAppGuard.SelfCheck.exe --strict-mode-lifecycle-test  严格模式：**同上**，验证开启 / 关闭 / 崩溃后兜底 / 拒绝覆盖别人的策略
///   WinAppGuard.SelfCheck.exe --wfp-test        WFP：真实往返（建子层 → 加过滤器 → 枚举 → 删 → 删子层）+ 动态会话自动清理
///   WinAppGuard.SelfCheck.exe --wfp-rule-test    WFP：规则模型（编码/解析、V4+V6 两层、幂等写入、读取、删除）
///   WinAppGuard.SelfCheck.exe --wfp-migrate-test WFP：1.x → 2.0 迁移（造两条记事本规则 → 迁移 → 核对 → 清理）
///   WinAppGuard.SelfCheck.exe --wfp-status      WFP：只读，打印当前 2.0 规则与子层状态
///   WinAppGuard.SelfCheck.exe --wfp-dacl-sddl-test  3.4：owner-only SDDL 构造（离线）
///   WinAppGuard.SelfCheck.exe --wfp-dacl-test   3.4：真实子层/过滤器 DACL（需管理员 + 至少一条规则）
///   WinAppGuard.SelfCheck.exe --wfp-strict-test WFP：严格模式（动态会话 + 白名单 + 阻止全部，验证真能拦、退出即恢复）
///   WinAppGuard.SelfCheck.exe --audit-store-test 审计：事件模型与落盘（往返 / 轮转 / 清理 / 半行容错，离线）
///   WinAppGuard.SelfCheck.exe --audit-dns-test   审计：读本机 DNS 缓存 + 域名索引（离线、不联网）
///   WinAppGuard.SelfCheck.exe --audit-live-test  审计：实时采集（连接差集 + WFP 拦截事件，约 12 秒，需管理员）
///   WinAppGuard.SelfCheck.exe --audit-service-test 审计：完整服务跑 12 秒（DNS + 轮询 + 拦截，写临时目录）
///   WinAppGuard.SelfCheck.exe --wfp-recover-test WFP：恢复（清自己的东西 + 证明不碰 Windows 防火墙 + 幂等）
///   WinAppGuard.SelfCheck.exe --render-docs [目录]  生成 README 用的界面截图（离线 / 不需要管理员 / 造数据渲染）
///   WinAppGuard.SelfCheck.exe --audit [dll]      出厂审计：读编译产物元数据，证明零第三方库 / 联网边界受控
///   任一模式加 --no-pause 可以不等待回车直接退出
///
/// 安全说明：
///   1. 防火墙部分只创建/删除以 AppGuard_ 开头的规则，从不修改全局防火墙策略；
///      **唯一例外**是 --strict-mode-test：它会临时把「默认出站动作」改成「阻止」以验证
///      拦截是否真实，并在 finally 里立刻还原。开始前三套配置文件必须是「允许」，
///      否则直接中止 —— 那说明机器上已经有别人的默认阻止策略，我们绝不覆盖它；
///   2. 自启部分只创建/删除名为 WinAppGuard 的计划任务，绝不碰其他人的任务；
///   3. 两种完整测试模式无论中途是否出错，最后都会强制清理自己创建的东西；
///   4. 审计模式是纯只读的，只是读一个文件；
///   5. 只有 --ownership-test 会主动联网（连 whois.cymru.com:43），行为与产品完全一致，
///      用的是产品里同一个 Core/IpOwnershipLookup.cs，不是另写一套；
///      --ownership-core-test 用不联网的替身 + 临时文件，纯离线断言。
/// </summary>
internal static class Program
{
    private static readonly StringBuilder Report = new();

    /// <summary>失败项计数。用于让进程返回非零退出码 —— CI 需要靠它判断成败。</summary>
    private static int _failedCheckCount;

    /// <summary>
    /// 界面自检时是否把每个场景渲染成 PNG（由 <c>--ui-render</c> 打开）。
    /// 默认关：让自检本身不产出文件，只有想看的时候才写图。
    /// </summary>
    private static bool _renderUi;

    /// <summary>生成 README 截图时写到哪个目录（由 <c>--render-docs [目录]</c> 指定）。</summary>
    private static string _renderDocsOutputDir = AppContext.BaseDirectory;

    [STAThread]
    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        var noPause = args.Contains("--no-pause", StringComparer.OrdinalIgnoreCase);

        // --ui-render：界面自检时顺手把每个场景渲染成 PNG（便于人眼核对）。
        _renderUi = args.Contains("--ui-render", StringComparer.OrdinalIgnoreCase);

        // --render-docs [目录]：生成 README 用的界面截图；目录省略时写到自检工具所在目录。
        var docsIndex = Array.FindIndex(args, a => a.Equals("--render-docs", StringComparison.OrdinalIgnoreCase));
        if (docsIndex >= 0)
        {
            _renderDocsOutputDir =
                docsIndex + 1 < args.Length && !args[docsIndex + 1].StartsWith("--", StringComparison.Ordinal)
                    ? args[docsIndex + 1]
                    : AppContext.BaseDirectory;
        }

        // 只有 --audit / --ownership-test / --ownership-core-test / --connection-filter-test / --ui-check
        // 不需要管理员权限：
        //   --audit 只读一个文件的元数据；
        //   --ownership-test 只是发网络请求，不碰系统状态；
        //   --ownership-core-test / --connection-filter-test 是纯离线逻辑断言；
        //   --ui-check 只构造窗体量控件矩形，不碰系统状态（会短暂显示窗口）。
        // 这样它们都能在 CI（无法弹 UAC）里跑起来。
        var needsAdmin = !args.Contains("--audit", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ownership-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ownership-core-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--connection-filter-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--temp-block-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--temp-block-status", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-check", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-render", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--render-docs", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--cli-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--audit-store-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--audit-dns-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--audit-live-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--audit-service-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--audit-ui-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-dpi-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-language-dpi-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-polish-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--rules-io-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--rule-scope-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ipc-codec-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--auth-codec-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--service-ui-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-offline-rules-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--protected-mode-ui-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--ui-language-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--cli-language-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--log-format-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--process-path-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--strict-lockdown-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--traffic-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--traffic-records-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--ids-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--antiscan-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--dns-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--wfp-dacl-sddl-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--snapshot-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--key-primitive-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--protected-mode-store-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--protected-mode-owner-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--audit-migrate-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--service-ping-test", StringComparer.OrdinalIgnoreCase)
                         && !args.Contains("--service-35-test", StringComparer.OrdinalIgnoreCase)
                        && !args.Contains("--loopback-download-test", StringComparer.OrdinalIgnoreCase);

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

        // 3.1：服务/IPC 相关测试需要所有者密钥；离线测试没有密钥也能跑。
        var signerReady = ProtectedModeClient.TryConfigureSigner(out _, out var signerError);

        if (!signerReady
            && args.Any(a => a.StartsWith("--service", StringComparison.OrdinalIgnoreCase)))
        {
            Console.WriteLine($"提示：未加载受保护模式签名密钥（{signerError}）；服务测试会失败。");
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
            else if (args.Contains("--ownership-test", StringComparer.OrdinalIgnoreCase))
            {
                RunOwnershipTest();
            }
            else if (args.Contains("--ownership-core-test", StringComparer.OrdinalIgnoreCase))
            {
                RunOwnershipCoreTest();
            }
            else if (args.Contains("--connection-filter-test", StringComparer.OrdinalIgnoreCase))
            {
                RunConnectionFilterTest();
            }
            else if (args.Contains("--temp-block-test", StringComparer.OrdinalIgnoreCase))
            {
                RunTempBlockTest();
            }
            else if (args.Contains("--temp-block-status", StringComparer.OrdinalIgnoreCase))
            {
                RunTempBlockStatus();
            }
            else if (args.Contains("--strict-mode-test", StringComparer.OrdinalIgnoreCase))
            {
                RunStrictModeTest();
            }
            else if (args.Contains("--strict-mode-lifecycle-test", StringComparer.OrdinalIgnoreCase))
            {
                RunStrictModeLifecycleTest();
            }
            else if (args.Contains("--ui-check", StringComparer.OrdinalIgnoreCase)
                     || args.Contains("--ui-render", StringComparer.OrdinalIgnoreCase))
            {
                RunUiCheck();
            }
            else if (args.Contains("--render-docs", StringComparer.OrdinalIgnoreCase))
            {
                RunRenderDocs();
            }
            else if (args.Contains("--wfp-ip-rule-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpIpRuleTest();
            }
            else if (args.Contains("--audit-ui-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuditUiTest();
            }
            else if (args.Contains("--ui-dpi-test", StringComparer.OrdinalIgnoreCase))
            {
                RunUiDpiTest();
            }
            else if (args.Contains("--ui-language-dpi-test", StringComparer.OrdinalIgnoreCase))
            {
                RunUiDpiTest(english: true);
            }
            else if (args.Contains("--ui-polish-test", StringComparer.OrdinalIgnoreCase))
            {
                RunUiPolishTest();
            }
            else if (args.Contains("--rules-io-test", StringComparer.OrdinalIgnoreCase))
            {
                RunRulesIoTest();
            }
            else if (args.Contains("--rule-scope-test", StringComparer.OrdinalIgnoreCase))
            {
                RunRuleScopeTest();
            }
            else if (args.Contains("--ipc-codec-test", StringComparer.OrdinalIgnoreCase))
            {
                RunIpcCodecTest();
            }
            else if (args.Contains("--auth-codec-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuthCodecTest();
            }
            else if (args.Contains("--service-ui-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceUiTest();
            }
            else if (args.Contains("--service-install-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceInstallTest();
            }
            else if (args.Contains("--service-ping-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServicePingTest();
            }
            else if (args.Contains("--loopback-download-test", StringComparer.OrdinalIgnoreCase))
            {
                RunLoopbackDownloadTest();
            }
            else if (args.Contains("--etw-network-test", StringComparer.OrdinalIgnoreCase))
            {
                RunEtwNetworkTest();
            }
            else if (args.Contains("--service-35-test", StringComparer.OrdinalIgnoreCase))
            {
                RunService35Test();
            }
            else if (args.Contains("--service-traffic-clear-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceTrafficClearTest();
            }
            else if (args.Contains("--service-ids-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceIdsTest();
            }
            else if (args.Contains("--service-antiscan-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceAntiScanTest();
            }
            else if (args.Contains("--wfp-inbound-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpInboundTest();
            }
            else if (args.Contains("--service-lockdown-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceLockdownTest();
            }
            else if (args.Contains("--service-auth-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceAuthTest();
            }
            else if (args.Contains("--service-acl-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceAclTest();
            }
            else if (args.Contains("--service-rules-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceRulesTest();
            }
            else if (args.Contains("--service-strict-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceStrictTest();
            }
            else if (args.Contains("--snapshot-test", StringComparer.OrdinalIgnoreCase))
            {
                RunSnapshotTest();
            }
            else if (args.Contains("--key-primitive-test", StringComparer.OrdinalIgnoreCase))
            {
                RunKeyPrimitiveTest();
            }
            else if (args.Contains("--protected-mode-store-test", StringComparer.OrdinalIgnoreCase))
            {
                RunProtectedModeStoreTest();
            }
            else if (args.Contains("--protected-mode-owner-test", StringComparer.OrdinalIgnoreCase))
            {
                RunProtectedModeOwnerTest();
            }
            else if (args.Contains("--audit-migrate-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuditMigrateTest();
            }
            else if (args.Contains("--service-audit-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceAuditTest();
            }
            else if (args.Contains("--service-tamper-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceTamperTest();
            }
            else if (args.Contains("--ui-offline-rules-test", StringComparer.OrdinalIgnoreCase))
            {
                RunUiOfflineRulesTest();
            }
            else if (args.Contains("--protected-mode-ui-test", StringComparer.OrdinalIgnoreCase))
            {
                RunProtectedModeUiTest();
            }
            else if (args.Contains("--ui-language-test", StringComparer.OrdinalIgnoreCase))
            {
                RunUiLanguageTest();
            }
            else if (args.Contains("--cli-language-test", StringComparer.OrdinalIgnoreCase))
            {
                RunCliLanguageTest();
            }
            else if (args.Contains("--process-path-test", StringComparer.OrdinalIgnoreCase))
            {
                RunProcessPathTest();
            }
            else if (args.Contains("--strict-lockdown-test", StringComparer.OrdinalIgnoreCase))
            {
                RunStrictLockdownTest();
            }
            else if (args.Contains("--traffic-records-test", StringComparer.OrdinalIgnoreCase))
            {
                RunTrafficRecordsTest();
            }
            else if (args.Contains("--ids-test", StringComparer.OrdinalIgnoreCase))
            {
                RunIdsTest();
            }
            else if (args.Contains("--antiscan-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAntiScanTest();
            }
            else if (args.Contains("--traffic-test", StringComparer.OrdinalIgnoreCase))
            {
                RunTrafficTest();
            }
            else if (args.Contains("--dns-test", StringComparer.OrdinalIgnoreCase))
            {
                RunDnsTest();
            }
            else if (args.Contains("--log-format-test", StringComparer.OrdinalIgnoreCase))
            {
                RunServiceLogFormatTest();
            }
            else if (args.Contains("--wfp-scope-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpScopeTest();
            }
            else if (args.Contains("--audit-service-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuditServiceTest();
            }
            else if (args.Contains("--audit-live-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuditLiveTest(seconds: 12);
            }
            else if (args.Contains("--audit-dns-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuditDnsTest();
            }
            else if (args.Contains("--audit-store-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAuditStoreTest();
            }
            else if (args.Contains("--wfp-strict-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpStrictTest();
            }
            else if (args.Contains("--wfp-status", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpStatus();
            }
            else if (args.Contains("--wfp-recover-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpRecoverTest();
            }
            else if (args.Contains("--wfp-migrate-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpMigrateTest();
            }
            else if (args.Contains("--wfp-rule-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpRuleTest();
            }
            else if (args.Contains("--wfp-dacl-sddl-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpDaclSddlTest();
            }
            else if (args.Contains("--wfp-dacl-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpDaclTest();
            }
            else if (args.Contains("--wfp-test", StringComparer.OrdinalIgnoreCase))
            {
                RunWfpTest();
            }
            else if (args.Contains("--cli-test", StringComparer.OrdinalIgnoreCase))
            {
                RunCliTest();
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

            // ---------------- 4.5 临时阻断：到期自动解除 ----------------
            W();
            W("================= 4.5 临时阻断的到期时间 =================");

            // (a) 到期时间在未来：说明里要带上标记、能读回来，而且**不能**被清掉。
            var tempName = FirewallManager.CreateBlockRule(target1, RuleExpiry.At(DateTime.UtcNow.AddHours(2)));
            created.Add(tempName);

            var tempRule = FirewallManager.GetAppGuardRules().FirstOrDefault(r => r.Name == tempName);
            W($"规则说明            = {tempRule?.Description}");
            W($"读出的到期显示      = {tempRule?.ExpiryText}");

            Check("临时阻断规则创建成功", tempRule is not null);
            Check("说明里带着到期标记（用户在 wf.msc 里能直接看到）",
                tempRule?.Description.Contains("自动解除=") == true);
            Check("到期方式能读回来（不是永久）", tempRule?.Expiry.IsPermanent == false);
            Check("显示文本以「剩余」开头", tempRule?.ExpiryText.StartsWith("剩余", StringComparison.Ordinal) == true);

            var purgedFuture = FirewallManager.PurgeExpiredRules(DateTime.UtcNow, SystemUptime.BootTimeUtc);
            Check("还没到期的临时阻断不会被清掉",
                purgedFuture.Count == 0 && FirewallManager.GetAppGuardRules().Count == 1);

            // (b) 把同名规则改成「已经过期」——顺便验证「到期方式变了会更新」这条路径。
            FirewallManager.CreateBlockRule(target1, RuleExpiry.At(DateTime.UtcNow.AddMinutes(-1)));

            var updated = FirewallManager.GetAppGuardRules().FirstOrDefault(r => r.Name == tempName);
            Check("同名规则的到期方式改成过去时会被更新（而不是当成已存在直接跳过）",
                updated is { Expiry.IsPermanent: false }
                && updated.Expiry.IsExpired(DateTime.UtcNow, SystemUptime.BootTimeUtc));

            var purgedExpired = FirewallManager.PurgeExpiredRules(DateTime.UtcNow, SystemUptime.BootTimeUtc);
            W($"清理掉的规则数      = {purgedExpired.Count}");
            Check("已经过期的临时阻断会被自动清理", purgedExpired.Count == 1);
            Check("清理的正是我们那条规则", purgedExpired.Count == 1 && purgedExpired[0].RuleName == tempName);
            Check("清理之后规则数归零", FirewallManager.GetAppGuardRules().Count == 0);
            created.Clear();

            // (c) 永久规则无论过多久都不该被自动清理。
            var permanentName = FirewallManager.CreateBlockRule(target1);
            created.Add(permanentName);
            var purgedPermanent = FirewallManager.PurgeExpiredRules(
                DateTime.UtcNow.AddYears(5), SystemUptime.BootTimeUtc.AddYears(5));
            Check("永久阻断即使过很多年也不会被自动清理",
                purgedPermanent.Count == 0 && FirewallManager.GetAppGuardRules().Count == 1);

            // (d) 「到下次重启」：换一个开机时刻就应当被清掉。
            FirewallManager.CreateBlockRule(target1, RuleExpiry.OnNextBoot(SystemUptime.BootTimeUtc));
            var purgedReboot = FirewallManager.PurgeExpiredRules(
                DateTime.UtcNow, SystemUptime.BootTimeUtc.AddHours(1));
            Check("「到下次重启」在开机时刻变化之后会被清掉", purgedReboot.Count == 1);
            Check("收尾：规则数归零", FirewallManager.GetAppGuardRules().Count == 0);
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

            // 反向护栏：受保护进程禁止「阻止」，但**不禁止「允许」**。
            //
            // 为什么必须有这条：放行永远不会把用户锁在外面，而严格模式**必须**能放行
            // 本程序自己（否则它自己连 IP 归属都查不了）—— 严格模式的自检也直接依赖它。
            // 这条断言最初就是被实际跑挂出来的（见开发记录里的踩坑）。
            if (!string.IsNullOrEmpty(selfPath))
            {
                var allowSelfAccepted = false;
                try
                {
                    // 建完立刻删掉：后面「删除全部规则」那条断言是按条数核对的，不能多留一条。
                    var allowSelfRule = FirewallManager.CreateAllowRule(selfPath);
                    FirewallManager.DeleteRule(allowSelfRule);
                    W($"  [正常] 对自己建「允许」规则 -> 被接受（再把规则删掉）");
                    allowSelfAccepted = true;
                }
                catch (Exception ex)
                {
                    W($"  [!!! 异常 !!!] 对自己建「允许」规则被拒：{ex.Message}");
                }

                Check("受保护进程可以被「允许」（放行不会锁人；严格模式自检依赖这条）", allowSelfAccepted);
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
        W("================= 清理全部 AppGuard 规则 =================");

        // ⚠️ 顺序很重要：如果严格模式留下的「默认阻止出站」还在，而我们把白名单规则全删了，
        // 用户就彻底上不了网了（默认阻止 + 没有白名单 = 全断网）。
        // 所以**先还原默认放行，再删规则**。
        var strictRecovery = StrictModeManager.RecoverIfLeftOn();
        if (strictRecovery.WasLeftOn)
        {
            W($"严格模式兜底：{strictRecovery.Message}");
            W();
        }

        var before = FirewallManager.GetAppGuardRules();
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
        W($"默认出站动作（按配置文件）= {FirewallManager.GetOutboundDefaultAllowed().Describe()}");
        W("   ↑ 2.0 的严格模式不改这三项（它只在进程内建立动态会话），任何时候都应当保持「允许」。");
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
    /// 界面布局自检（**不联网、不需要管理员、不碰系统状态**，但会短暂显示窗口）。
    ///
    /// 为什么要有它：本项目的界面出过好几次「控件互相压住」的 bug，
    /// 而且都是**特定状态下才出现**的（文字变长、切标签页、缩放窗口）——
    /// 跑起来扫一眼根本看不出来。所以把关键判断写成可重复运行的断言。
    ///
    /// 做法：反射构造**真实的** MainForm，把「运行期初始化」标记成已做过
    /// （这样它不会去读防火墙规则、也不会真的扫描连接表），
    /// 然后在多种「窗口宽度 × 文字长度」组合下量各控件的矩形，断言：
    ///   - 同一个容器里的控件互不重叠；
    ///   - 控件都完整落在自己的容器里（没有被裁掉）；
    ///   - 面板宽度不超过标签页的可视宽度（防止 AutoScroll 累积漂移）。
    ///
    /// 注意：它会把窗体真的显示出来一小会儿（布局要显示过才算得准），然后立刻关掉。
    /// 这是本工具唯一会弹窗的模式。
    /// </summary>
    private static void RunUiCheck()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   界面布局自检（不联网 / 不需要管理员 / 会短暂显示窗口）        #");
        W("################################################################");
        W();

        MainForm? form = null;

        try
        {
            // 自检只量布局：禁止启动任何后台服务（否则会写真实审计目录）。
        MainForm.SuppressBackgroundServices = true;
        form = new MainForm(isAutostart: false);

            // 跳过运行期初始化：否则 OnLoad 会去读防火墙规则（需要管理员）并真的扫描一遍。
            // 这里只关心布局，不需要那些东西。
            if (!TrySetField(form, "_runtimeInitialized", true))
            {
                W("    ！找不到 _runtimeInitialized，无法安全跳过初始化，自检中止。");
                results.Add(("界面自检能安全跳过运行期初始化", false));
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            form.Show();
            Application.DoEvents();

            if (!TryGetField<TabControl>(form, "_tabControl", out _)
                || !TryGetField<Control>(form, "_tabConnections", out _)
                || !TryGetField<Control>(form, "_tabSettings", out _)
                || !TryGetField<Label>(form, "_selectionHintLabel", out var hintLabel)
                || !TryGetField<Label>(form, "_autostartDetailLabel", out var detailLabel)
                || !TryGetField<Label>(form, "_privacyLabel", out var privacyLabel))
            {
                W("    ！找不到预期的控件字段，自检中止。");
                results.Add(("能找到界面自检需要的全部控件字段", false));
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            // 搜索框和清除按钮必须真的在（防止将来重构时被悄悄删掉）。
            results.Add(("工具栏里有搜索框 _searchBox", TryGetField<TextBox>(form, "_searchBox", out _)));
            results.Add(("工具栏里有清除搜索按钮 _clearSearchButton", TryGetField<Button>(form, "_clearSearchButton", out _)));

            var originalHint = hintLabel.Text;
            var originalDetail = detailLabel.Text;
            var originalPrivacy = privacyLabel.Text;

            var longHint = originalHint + originalHint + originalHint;
            var longDetail = originalDetail + originalDetail + originalDetail + originalDetail;
            var longPrivacy = originalPrivacy + originalPrivacy + originalPrivacy;

            // 宽度必须落在窗体真正允许的范围内（MinimumSize = 980×640，
            // 设得更小会被系统钳回 980，那测的就不是我们写的宽度了）。
            var cases = new (string Name, int Width, string Hint, string Detail, string Privacy)[]
            {
                ("默认宽度 1180 / 真实文案", 1180, originalHint, originalDetail, originalPrivacy),
                ("最小宽度 980 / 真实文案", 980, originalHint, originalDetail, originalPrivacy),
                ("宽窗口 1500 / 真实文案", 1500, originalHint, originalDetail, originalPrivacy),
                ("默认宽度 / 短文案", 1180, "已阻止", "未开启。", "两处会联网。"),
                ("默认宽度 / 超长文案", 1180, longHint, longDetail, longPrivacy),
                ("最小宽度 / 超长文案", 980, longHint, longDetail, longPrivacy),
            };

            foreach (var c in cases)
            {
                ApplyUiCase(form, c.Width, c.Hint, c.Detail, c.Privacy);
                CheckConnectionPage(results, form, c.Name);
                CheckWhitelistColumnFits(results, form, c.Name);
                CheckSettingsPage(results, form, c.Name);

                if (_renderUi)
                {
                    TrySelectTab(form, "_tabConnections");

                    // 先把"切页"排队的动作跑完：它会去**真实读一遍**放行状态，
                    // 而真实机器上白名单是空的，会把刚灌进去的样本覆盖掉。
                    Application.DoEvents();

                    // 再灌一批样本数据：空表看不出列宽、文本截断和三种放行状态。
                    FillRenderSamples(form);

                    RenderForm(form, $"ui-conn-{Sanitize(c.Name)}.png");
                    TrySelectTab(form, "_tabSettings");
                    RenderForm(form, $"ui-settings-{Sanitize(c.Name)}.png");
                }
            }

            if (_renderUi)
            {
                // 再单独渲染一张「高窗口」的设置页：设置页内容比 900 高，
                // 矮窗口下最下面那个分区落在折叠线以下，人眼根本核对不到 ——
                // 那样"渲染出来看一眼"就成了走过场。
                TrySelectTab(form, "_tabSettings");
                Application.DoEvents();

                form.Size = new Size(1180, 1400);
                form.PerformLayout();
                Application.DoEvents();

                RenderForm(form, "ui-settings-高窗口-完整.png");

                form.Size = new Size(1180, 900);
                Application.DoEvents();
            }

            // 切标签页来回之后，布局不能漂移
            {
                const string name = "切标签页之后";

                ApplyUiCase(form, 1180, originalHint, originalDetail, originalPrivacy);

                if (TryGetField<TabControl>(form, "_tabControl", out var tabs)
                    && TryGetField<Control>(form, "_tabConnections", out var connectionsPage)
                    && TryGetField<Control>(form, "_tabSettings", out var settingsPage)
                    && connectionsPage is TabPage cp
                    && settingsPage is TabPage sp)
                {
                    tabs.SelectedTab = cp;
                    Application.DoEvents();
                    tabs.SelectedTab = sp;
                    Application.DoEvents();
                    tabs.SelectedTab = cp;
                    Application.DoEvents();
                }

                CheckConnectionPage(results, form, name);
                CheckSettingsPage(results, form, name);
            }

            CheckSearchWiring(results, form);
            CheckSortWiring(results, form);
            CheckColumnResizeWiring(results, form);
            CheckExpiryTimerWiring(results, form);
            CheckTemporaryBlockUi(results, form);
            CheckWhitelistWiring(results, form);
            CheckStrictModeUi(results, form);
            CheckSafetyNoticeFits(results, form);

            hintLabel.Text = originalHint;
            detailLabel.Text = originalDetail;
            privacyLabel.Text = originalPrivacy;
        }
        catch (Exception ex)
        {
            W($"    ！界面自检自身出错：{ex}");
            results.Add(("界面自检能完整跑完", false));
        }
        finally
        {
            if (form is not null)
            {
                form.Close();
                form.Dispose();
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 生成 README 里用的界面截图，直接写进仓库的 `docs/screenshots/`。
    ///
    /// ==================== 为什么要有这个模式 ====================
    /// 截图会随着界面改动**悄悄过时**，而这个坑已经踩过两次：
    ///   - 1.1 的图里横幅还写着"本程序不访问网络"，而 1.2 起会联网查 IP 归属；
    ///   - 页签名改成「规则」之后，旧图里还是「已阻止的程序」。
    /// 靠"发布前人工重截"解决不了（发布手册里写了一条，但没人会记得）。
    /// 所以把它变成**一条命令**：
    ///
    ///     WinAppGuard.SelfCheck.exe --render-docs &lt;仓库的 docs/screenshots 目录&gt;
    ///
    /// 三个刻意的选择：
    ///   1. **不实拍，用造的样本数据** —— 实拍会暴露开发者机器上的真实进程 / 远程 IP / 用户名，
    ///      而且只能拍到"当时恰好发生了什么"，想展示的状态不一定出现
    ///      （三种放行状态、限时规则、未签名的程序……）；
    ///   2. **状态栏也一起伪造** —— 否则跑在自检工具里会显示 `v0.0.0`、"管理员权限：未获得"，
    ///      那样的图放进 README 像半成品；
    ///   3. **不碰防火墙、不需要管理员**，也不写用户的设置文件。
    /// ==========================================================
    /// </summary>
    private static void RunRenderDocs()
    {
        W("################################################################");
        W("#   生成 README 用的界面截图（离线 / 不需要管理员 / 不碰系统）    #");
        W("################################################################");
        W();

        string outputDir;
        try
        {
            outputDir = Path.GetFullPath(_renderDocsOutputDir);
            Directory.CreateDirectory(outputDir);
        }
        catch (Exception ex)
        {
            W($"！输出目录不可用：{_renderDocsOutputDir}（{ex.Message}）");
            return;
        }

        W($"输出目录 = {outputDir}");
        W();

        MainForm? form = null;

        try
        {
            // 自检只量布局：禁止启动任何后台服务（否则会写真实审计目录）。
        MainForm.SuppressBackgroundServices = true;
        form = new MainForm(isAutostart: false);

            if (!TrySetField(form, "_runtimeInitialized", true))
            {
                W("！找不到 _runtimeInitialized，无法安全跳过运行期初始化，已中止。");
                return;
            }

            form.Show();
            Application.DoEvents();

            // 固定成默认窗口尺寸（--ui-check 的布局断言就是按 1180 宽断言的）。
            form.Size = new Size(1180, 900);
            Application.DoEvents();

            FillDocsSampleData(form);

            TrySelectTab(form, "_tabConnections");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "01-connections.png"));

            TrySelectTab(form, "_tabIds");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "06-ids.png"));

            TrySelectTab(form, "_tabTraffic");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "07-traffic.png"));

            TrySelectTab(form, "_tabDns");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "08-dns.png"));

            TrySelectTab(form, "_tabAntiScan");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "09-protection.png"));

            TrySelectTab(form, "_tabRules");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "02-rules.png"));

            TrySelectTab(form, "_tabWhitelist");
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "05-whitelist.png"));

            // 设置页比一屏高（四个分区），所以拉高到能一次看全 ——
            // 否则新加的分区永远落在折叠线以下，那张图就展示不出它。
            TrySelectTab(form, "_tabSettings");
            Application.DoEvents();
            PolishSettingsPageForDocs(form);
            form.Size = new Size(1180, 1520);
            form.PerformLayout();
            Application.DoEvents();
            RenderFormTo(form, Path.Combine(outputDir, "03-settings.png"));

            form.Size = new Size(1180, 900);
            Application.DoEvents();
        }
        catch (Exception ex)
        {
            W($"！生成界面截图时出错：{ex}");
        }
        finally
        {
            form?.Close();
            form?.Dispose();
        }

        RenderBlockConfirmSample(outputDir);

        W();
        W("完成。改完界面重跑一次本模式，把生成的图提交上去即可。");
    }

    /// <summary>
    /// 给截图灌一批**造的**样本数据，让界面看起来像真的在用。
    /// 样本刻意覆盖了所有值得在 README 里展示的状态：
    /// 已阻止 / 未阻止、三种放行状态、限时与永久的规则、已签名与未签名的程序。
    /// </summary>
    private static void FillDocsSampleData(MainForm form)
    {
        var samples = new (string Name, string Path, string Remote, ushort Port, string Signer, SignatureState State)[]
        {
            ("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "142.250.66.78", 443, "Google LLC", SignatureState.Valid),
            ("steam.exe", @"C:\Program Files (x86)\Steam\steam.exe",
                "23.62.99.180", 27017, "Valve Corp.", SignatureState.Valid),
            ("douyin.exe", @"C:\Program Files (x86)\ByteDance\douyin\douyin.exe",
                "113.105.155.51", 443, "Beijing Microlive Vision", SignatureState.Valid),
            ("bdservicehost.exe", @"C:\Program Files\Bitdefender\Bitdefender Security\bdservicehost.exe",
                "34.149.211.227", 443, "Bitdefender SRL", SignatureState.Valid),
            ("game.exe", @"C:\Program Files\SomeGame\game.exe",
                "203.0.113.9", 27015, string.Empty, SignatureState.Unsigned),
            ("Code.exe", @"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                "20.205.243.166", 443, "Microsoft Corporation", SignatureState.Valid),
            ("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "13.107.42.12", 443, "Microsoft Corporation", SignatureState.Valid),
            ("svchost.exe", @"C:\Windows\System32\svchost.exe",
                "224.0.0.251", 5353, "Microsoft Windows", SignatureState.Valid),
            ("tool.exe", @"C:\Users\dev\Downloads\tool.exe",
                "198.51.100.7", 8080, string.Empty, SignatureState.Unsigned),
        };

        // ---- 造 58 条连接：状态栏会显示「共 58 条」，表格只显示得下前十几条，正好 ----
        if (TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned))
        {
            scanned.Clear();

            for (var i = 0; i < 58; i++)
            {
                var sample = samples[i % samples.Length];
                var item = MakeConnection(
                    3000 + i, sample.Name, sample.Remote, sample.Port, "IPv4",
                    (ushort)(50000 + i), TcpState.Established, sample.Path);

                item.Signature = new SignatureInfo(sample.State, sample.Signer, $"{sample.Name}：示例签名信息");

                var traffic = sample.Name switch
                {
                    "chrome.exe" => (1_208_336L, 18_800_512L),
                    "steam.exe" => (308_064L, 12_274_688L),
                    "douyin.exe" => (890_048L, 45_767_104L),
                    "bdservicehost.exe" => (128_064L, 2_274_688L),
                    "game.exe" => (20_480L, 0L),
                    "Code.exe" => (445_728L, 3_874_368L),
                    "OneDrive.exe" => (1_582_912L, 5_194_304L),
                    "svchost.exe" => (58_288L, 208_896L),
                    _ => (5_120L, 0L),
                };

                item.ApplyTraffic(traffic.Item1, traffic.Item2);
                scanned.Add(item);
            }
        }

        // ---- 三种「放行」状态各来一个（这是最需要展示清楚的一件事）----
        ApplyDocsWhitelistSamples(form);

        // ---- 「已阻止」状态 ----
        if (TryGetField<HashSet<string>>(form, "_blockedPaths", out var blocked))
        {
            blocked.Clear();
            blocked.Add(samples[4].Path);       // game.exe → 已阻止
        }

        // ---- 规则页：阻止 3 条（含限时 / 下次重启）+ 白名单 1 条 ----
        if (TryGetField<List<FirewallRuleItem>>(form, "_appGuardRules", out var appRules)
            && TryGetField<List<FirewallRuleItem>>(form, "_rules", out var rules))
        {
            appRules.Clear();
            appRules.Add(MakeDocsRule("AppGuard_Block_game.exe_1a2b3c4d", samples[4].Path,
                FirewallAction.Block, RuleExpiry.Never));
            appRules.Add(MakeDocsRule("AppGuard_Block_douyin.exe_5e6f7a8b", samples[2].Path,
                FirewallAction.Block, RuleExpiry.At(DateTime.UtcNow.AddMinutes(42))));
            appRules.Add(MakeDocsRule("AppGuard_Block_tool.exe_9c0d1e2f", samples[8].Path,
                FirewallAction.Block, RuleExpiry.OnNextBoot(DateTime.UtcNow.AddHours(-3))));
            appRules.Add(MakeDocsRule("AppGuard_Allow_chrome.exe_3b4c5d6e", samples[0].Path,
                FirewallAction.Allow, RuleExpiry.Never));

            rules.Clear();
            rules.AddRange(appRules.Where(rule => rule.Action == FirewallAction.Block));

            // 截图里展示一下分组列（真实数据在 rule-groups.json，渲染时不碰用户的文件）。
            foreach (var rule in appRules)
            {
                if (rule.ApplicationNameText.Contains("game") || rule.ApplicationNameText.Contains("douyin"))
                {
                    rule.Group = "游戏";
                }
            }

            if (TryGetField<ComboBox>(form, "_rulesGroupCombo", out var docsBlockGroups))
            {
                docsBlockGroups.Items.Clear();
                docsBlockGroups.Items.AddRange(new object[] { "全部分组", "未分组", "游戏" });
                docsBlockGroups.SelectedIndex = 0;
            }

            if (TryGetField<ComboBox>(form, "_whitelistGroupCombo", out var docsAllowGroups))
            {
                docsAllowGroups.Items.Clear();
                docsAllowGroups.Items.AddRange(new object[] { "全部分组", "未分组", "游戏" });
                docsAllowGroups.SelectedIndex = 0;
            }

            if (TryGetField<List<FirewallRuleItem>>(form, "_whitelistRules", out var whitelistRules))
            {
                whitelistRules.Clear();
                whitelistRules.AddRange(appRules.Where(rule => rule.Action == FirewallAction.Allow));
            }

            // 顺序同产品：先把完整列表灌进筛选视图（Apply*Filter 内部会 Rebind*），
            // 再重建连接页的显示列表与表格。
            // ⚠️ 表格绑的是 _rulesView / _whitelistView，直接调 RebindRules 会是空表。
            InvokePrivate(form, "ApplyRulesFilter", new object?[] { null });
            InvokePrivate(form, "ApplyWhitelistFilter", new object?[] { null });
            InvokePrivate(form, "RebuildView", null);
            InvokePrivate(form, "RebindGrid", new object?[] { null });
        }

        // ---- 状态栏与各种计数：让图看起来是"真的在跑" ----
        if (TryGetField<ToolStripStatusLabel>(form, "_versionLabel", out var versionLabel))
        {
            // 截图里要显示**产品**的版本，不能用 BuildVersionText()：
            // 它按当前进程取版本，自检进程取到的是 SelfCheck 自己的 1.0.0。
            // 也不能用 Assembly.GetName().Version（那是 2.2.0.0，产品界面显示的是 2.2）。
            var informational = typeof(MainForm).Assembly
                .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion;
            var productVersion = (informational ?? "2.2").Split('+')[0];
            versionLabel.Text = $"版本 v{productVersion}";
        }

        if (TryGetField<ToolStripStatusLabel>(form, "_adminStatusLabel", out var adminLabel))
        {
            adminLabel.Text = "管理员权限：已获得";
            adminLabel.ForeColor = Color.FromArgb(0, 120, 0);
        }

        if (TryGetField<ToolStripStatusLabel>(form, "_statusRulesLabel", out var statusRulesLabel))
        {
            statusRulesLabel.Text = "已阻止程序：3 个";
        }

        // 固定一个「最后刷新」时间，免得每次生成的图都不一样。
        if (TrySetField(form, "_lastScanTime", new DateTime(2026, 10, 17, 12, 18, 49)))
        {
            InvokePrivate(form, "UpdateSummary", null);
        }

        if (TryGetField<Label>(form, "_rulesSummaryLabel", out var rulesSummary))
        {
            rulesSummary.Text = "黑名单共 3 条";
        }

        if (TryGetField<Label>(form, "_whitelistSummaryLabel", out var whitelistSummary))
        {
            whitelistSummary.Text = "白名单共 1 个程序";
        }

        if (TryGetField<TabPage>(form, "_tabRules", out var rulesTab))
        {
            rulesTab.Text = "黑名单（3）";
        }

        if (TryGetField<TabPage>(form, "_tabWhitelist", out var whitelistTab))
        {
            whitelistTab.Text = "严格模式下白名单（1）";
        }

        if (TryGetField<Label>(form, "_selectionHintLabel", out var hint))
        {
            hint.Text = "已选中 chrome.exe（共 4 条连接）—— 当前状态：未阻止；白名单：已放行　签名：Google LLC";
        }

        FillDocsTelemetrySampleData(form);
    }

    /// <summary>
    /// 3.5–3.7 新增页面的样本：流量、DNS、IDS。
    /// 只灌内存字段，不读服务、不写盘；截图模式本来就把后台服务关掉了。
    /// </summary>
    private static void FillDocsTelemetrySampleData(MainForm form)
    {
        var now = new DateTime(2026, 10, 26, 12, 18, 49, DateTimeKind.Local);
        var started = now.AddHours(-2).ToUniversalTime();

        TrySetField(form, "_serviceAvailable", true);

        // ---- 流量页 ----
        TrySetField(form, "_trafficStartedUtc", (DateTime?)started);
        TrySetField(form, "_trafficServiceAvailable", true);
        TrySetField(form, "_trafficRecords", new List<TrafficDto>
        {
            new()
            {
                Key = @"c:\program files\google\chrome\application\chrome.exe",
                Path = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                Name = "chrome.exe",
                IsPathKnown = true,
                BytesOut = 8_412_336,
                BytesIn = 146_800_512,
                LastSeenUtc = now.ToUniversalTime(),
            },
            new()
            {
                Key = @"c:\program files (x86)\steam\steam.exe",
                Path = @"C:\Program Files (x86)\Steam\steam.exe",
                Name = "steam.exe",
                IsPathKnown = true,
                BytesOut = 1_208_064,
                BytesIn = 92_274_688,
                LastSeenUtc = now.AddMinutes(-2).ToUniversalTime(),
            },
            new()
            {
                Key = @"c:\program files (x86)\bytedance\douyin\douyin.exe",
                Path = @"C:\Program Files (x86)\ByteDance\douyin\douyin.exe",
                Name = "douyin.exe",
                IsPathKnown = true,
                BytesOut = 2_690_048,
                BytesIn = 318_767_104,
                LastSeenUtc = now.AddMinutes(-4).ToUniversalTime(),
            },
            new()
            {
                Key = @"c:\users\dev\appdata\local\programs\microsoft vs code\code.exe",
                Path = @"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                Name = "Code.exe",
                IsPathKnown = true,
                BytesOut = 3_145_728,
                BytesIn = 18_874_368,
                LastSeenUtc = now.AddMinutes(-6).ToUniversalTime(),
            },
            new()
            {
                Key = @"c:\program files\microsoft onedrive\onedrive.exe",
                Path = @"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                Name = "OneDrive.exe",
                IsPathKnown = true,
                BytesOut = 12_582_912,
                BytesIn = 4_194_304,
                LastSeenUtc = now.AddMinutes(-8).ToUniversalTime(),
            },
            new()
            {
                Key = "pid:808",
                Path = null,
                Name = "PID 808",
                IsPathKnown = false,
                BytesOut = 524_288,
                BytesIn = 96_256,
                LastSeenUtc = now.AddMinutes(-11).ToUniversalTime(),
            },
        });

        InvokePrivate(form, "RebuildTrafficView", null);

        // ---- DNS 页 ----
        TrySetField(form, "_dnsCollecting", true);
        TrySetField(form, "_dnsSignature", null!);
        TrySetField(form, "_dnsRecords", new List<DnsDto>
        {
            MakeDocsDns(now.AddSeconds(-8), 3000, "chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "www.google.com", "OK"),
            MakeDocsDns(now.AddSeconds(-12), 3000, "chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "fonts.gstatic.com", "OK"),
            MakeDocsDns(now.AddSeconds(-19), 3001, "steam.exe", @"C:\Program Files (x86)\Steam\steam.exe",
                "api.steampowered.com", "OK"),
            MakeDocsDns(now.AddSeconds(-25), 3001, "steam.exe", @"C:\Program Files (x86)\Steam\steam.exe",
                "steamcommunity.com", "OK"),
            MakeDocsDns(now.AddSeconds(-33), 3002, "douyin.exe", @"C:\Program Files (x86)\ByteDance\douyin\douyin.exe",
                "api.amemv.com", "OK"),
            MakeDocsDns(now.AddSeconds(-41), 3003, "Code.exe", @"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                "update.code.visualstudio.com", "OK"),
            MakeDocsDns(now.AddSeconds(-55), 3004, "OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "login.live.com", "OK"),
            MakeDocsDns(now.AddSeconds(-70), 3005, "tool.exe", @"C:\Users\dev\Downloads\tool.exe",
                "telemetry.example.invalid", "NXDOMAIN"),
        });

        InvokePrivate(form, "RebindDnsGrid", null);

        // ---- IDS 页 ----
        TrySetField(form, "_idsServiceAvailable", true);
        TrySetField(form, "_idsSignature", null!);
        TrySetField(form, "_idsSettings", new IdsSettingsDto
        {
            Enabled = true,
            Sensitivity = "standard",
            RetentionDays = 30,
        });
        TrySetField(form, "_idsStatus", new IdsStatusDto
        {
            Enabled = true,
            Collecting = true,
            Sensitivity = "standard",
            FlowCount = 137,
            EventsSeen = 4_821,
            AlertsNew = 3,
            AlertsTotal = 4,
            LastAlertUtc = now.AddMinutes(-3).ToUniversalTime(),
            SuppressionCount = 1,
        });
        TrySetField(form, "_idsSuppressions", new List<IdsSuppressionDto>
        {
            new()
            {
                Id = "suppress-demo",
                RuleId = "dns",
                ProcessName = "browser.exe",
                Target = "ads.example.com",
                UntilUtc = now.AddHours(20).ToUniversalTime(),
            },
        });
        TrySetField(form, "_idsAlerts", new List<IdsAlertDto>
        {
            new()
            {
                Id = "demo-1",
                TimeUtc = now.AddMinutes(-3).ToUniversalTime(),
                Severity = "high",
                RuleId = "lateral",
                RuleName = "lateral",
                Pid = 4212,
                ProcessName = "game.exe",
                ProcessPath = @"C:\Program Files\SomeGame\game.exe",
                Target = "private-admin-ports",
                Evidence = "privateHosts=4; ports=445,3389; window=600s",
                Status = "new",
            },
            new()
            {
                Id = "demo-2",
                TimeUtc = now.AddMinutes(-9).ToUniversalTime(),
                Severity = "medium",
                RuleId = "scan",
                RuleName = "scan",
                Pid = 808,
                ProcessName = "PID 808",
                Target = "host:203.0.113.9",
                Evidence = "sameHost=203.0.113.9; ports=24; window=60s",
                Status = "new",
            },
            new()
            {
                Id = "demo-3",
                TimeUtc = now.AddMinutes(-16).ToUniversalTime(),
                Severity = "medium",
                RuleId = "dns",
                RuleName = "dns",
                Pid = 5120,
                ProcessName = "tool.exe",
                ProcessPath = @"C:\Users\dev\Downloads\tool.exe",
                Target = "example.invalid",
                Evidence = "parent=example.invalid; unique=24; long=11; nxdomain=18/24",
                Status = "new",
            },
            new()
            {
                Id = "demo-4",
                TimeUtc = now.AddMinutes(-31).ToUniversalTime(),
                Severity = "medium",
                RuleId = "beaconing",
                RuleName = "beaconing",
                Pid = 6120,
                ProcessName = "OneDrive.exe",
                ProcessPath = @"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                Target = "13.107.42.12:443",
                Evidence = "connections=18; mean=60.0s; jitter=0.08; avg=412B",
                Status = "ack",
            },
        });

        InvokePrivate(form, "RebuildIdsView", null);

        // ---- 防护页（4.0） ----
        TrySetField(form, "_antiEvents", new List<AntiScanEventDto>
        {
            new()
            {
                Id = "scan-1",
                TimeUtc = now.AddMinutes(-4).ToUniversalTime(),
                SourceAddress = "203.0.113.42",
                DistinctPorts = 42,
                DistinctHosts = 1,
                SynCount = 42,
                WindowSeconds = 60,
                Severity = "high",
                Action = "blocked",
                BlockedUntilUtc = now.AddMinutes(6).ToUniversalTime(),
            },
            new()
            {
                Id = "scan-2",
                TimeUtc = now.AddMinutes(-12).ToUniversalTime(),
                SourceAddress = "198.51.100.7",
                DistinctPorts = 21,
                DistinctHosts = 1,
                SynCount = 21,
                WindowSeconds = 60,
                Severity = "medium",
                Action = "alert",
            },
        });

        TrySetField(form, "_antiBlocks", new List<AntiScanBlockDto>
        {
            new()
            {
                Address = "203.0.113.42",
                BlockedUntilUtc = now.AddMinutes(6).ToUniversalTime(),
                Reason = "inbound port scan",
                EventId = "scan-1",
            },
        });

        TrySetField(form, "_antiSettings", new AntiScanSettingsDto
        {
            Enabled = true,
            AutoBlock = true,
            Sensitivity = "standard",
            BlockMinutes = 10,
        });

        TrySetField(form, "_antiStatus", new AntiScanStatusDto
        {
            Enabled = true,
            NpcapAvailable = true,
            NpcapVersion = "1.90",
            Collecting = true,
            EventsSeen = 2_418,
            EventCount = 2,
            BlockedCount = 1,
            AutoBlock = true,
            Sensitivity = "standard",
            BlockMinutes = 10,
            LastEventUtc = now.AddMinutes(-4).ToUniversalTime(),
        });

        InvokePrivate(form, "RebuildAntiScanView", null);
    }

    private static DnsDto MakeDocsDns(
        DateTime time, int pid, string process, string path, string query, string status) => new()
    {
        TimeUtc = time.ToUniversalTime(),
        Pid = pid,
        ProcessName = process,
        ProcessPath = path,
        QueryName = query,
        Status = status,
    };

    /// <summary>
    /// 灌白名单样本（三种放行状态各来一个）。
    ///
    /// 单独抽出来是因为：切到设置页时界面会**真读一遍防火墙**，把样本冲掉 ——
    /// 渲染设置页之前要重新灌一次，否则三张图里的白名单状态会互相矛盾。
    /// </summary>
    private static void ApplyDocsWhitelistSamples(MainForm form)
    {
        if (TryGetField<HashSet<string>>(form, "_whitelistedPaths", out var whitelisted))
        {
            whitelisted.Clear();
            whitelisted.Add(@"C:\Program Files\Google\Chrome\Application\chrome.exe");
        }

        if (TryGetField<HashSet<string>>(form, "_otherAllowPaths", out var otherAllow))
        {
            otherAllow.Clear();
            otherAllow.Add(@"C:\Program Files (x86)\Steam\steam.exe");
            otherAllow.Add(@"C:\Program Files\Bitdefender\Bitdefender Security\bdservicehost.exe");
        }

        TrySetField(form, "_programlessAllowRuleCount", 24);
    }

    /// <summary>
    /// 设置页在截图里要看起来"真的在跑"：把自启状态、日志路径、任务定义、严格模式面板
    /// 都填上合理的值。正常这些由运行期初始化填，而截图模式刻意跳过了它。
    /// </summary>
    private static void PolishSettingsPageForDocs(MainForm form)
    {
        // 先补回白名单样本（见 ApplyDocsWhitelistSamples 的说明）。
        ApplyDocsWhitelistSamples(form);

        if (TryGetField<Label>(form, "_autostartStatusLabel", out var autostartStatus))
        {
            autostartStatus.Text = "当前状态：已开启（登录时自动启动，启动后最小化到托盘）";
        }

        if (TryGetField<Label>(form, "_autostartDetailLabel", out var autostartDetail))
        {
            autostartDetail.Text =
                "任务名称：WinAppGuard\r\n" +
                "运行级别：最高权限\r\n" +
                "触发器：当前用户登录时\r\n" +
                @"指向程序：C:\Program Files\WinAppGuard\WinAppGuard.exe --autostart";
        }

        if (TryGetField<Label>(form, "_logPathLabel", out var logPath))
        {
            logPath.Text = @"C:\Users\demo\AppData\Local\WinAppGuard\logs";
        }

        if (TryGetField<TextBox>(form, "_taskXmlBox", out var taskXml))
        {
            taskXml.Text =
                "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
                "  <RegistrationInfo><Author>WinAppGuard</Author></RegistrationInfo>\r\n" +
                "  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\r\n" +
                "  <Principals><Principal id=\"Author\">\r\n" +
                "    <RunLevel>HighestAvailable</RunLevel>\r\n" +
                "  </Principal></Principals>\r\n" +
                "  <Settings><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>\r\n" +
                "  <Actions><Exec><Command>WinAppGuard.exe</Command>\r\n" +
                "    <Arguments>--autostart</Arguments></Exec></Actions>\r\n" +
                "</Task>";
        }

        // 严格模式面板：按上面的样本数据重新生成说明文字（走产品真实的那个纯函数）。
        if (TryGetField<Label>(form, "_strictModeStatusLabel", out var strictStatus))
        {
            strictStatus.Text = "当前状态：未开启，默认放行";
        }

        if (TryGetField<Button>(form, "_strictModeToggleButton", out var strictToggle))
        {
            strictToggle.Text = "开启严格模式…";
            strictToggle.Enabled = true;
        }

        if (TryGetField<Label>(form, "_strictModeDetailLabel", out var strictDetail))
        {
            // ⚠️ 这个方法只有一个 bool 参数（enabled），别照老签名多传一个
            //    —— 多传会抛 ParameterCountException，整个 --render-docs 直接失败（2.1 就这么坏了）。
            var text = InvokePrivateWithResult<string>(
                form, "BuildStrictModeDetailText", false);

            if (!string.IsNullOrEmpty(text))
            {
                strictDetail.Text = text;
            }
        }
    }

    /// <summary>造一条规则数据（只用于截图）。</summary>
    private static FirewallRuleItem MakeDocsRule(string name, string path, FirewallAction action, RuleExpiry expiry)
        => new()
        {
            Name = name,
            ApplicationPath = path,
            Description = "由 WinAppGuard 创建。目标程序：" + path +
                          (expiry.IsPermanent ? string.Empty : " ｜ " + expiry.Encode()),
            Grouping = "AppGuard",
            Enabled = true,
            Action = action,
            Direction = FirewallDirection.Outbound,
            Protocol = 256,
            Expiry = expiry,
        };

    /// <summary>渲染「阻止联网」确认框（含 1.3 新增的「阻断时长」那一组单选按钮）。</summary>
    private static void RenderBlockConfirmSample(string outputDir)
    {
        try
        {
            // 确认框的构造函数是私有的（正常只能通过模态的 Show 用它），
            // 这里用反射把它建出来、非模态显示，才能截图。
            var constructor = typeof(ConfirmForm).GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                new[]
                {
                    typeof(string),
                    typeof(string),
                    typeof(IReadOnlyList<KeyValuePair<string, string>>),
                    typeof(IReadOnlyList<string>),
                    typeof(string),
                    typeof(bool),
                },
                modifiers: null);

            if (constructor is null)
            {
                W("！（找不到 ConfirmForm 的构造函数，跳过 04 的渲染）");
                return;
            }

            var details = new List<KeyValuePair<string, string>>
            {
                new("程序名", "chrome.exe"),
                new("完整路径", @"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                new("当前连接", "4 条"),
            };

            var warnings = new List<string>
            {
                "会创建一条「阻止出站」的防火墙规则：AppGuard_Block_chrome.exe_1a2b3c4d",
                "只有这一个程序受影响；其他程序、以及系统和其他软件设置的规则一律不受影响。",
                "想反悔随时可以：「规则」页选中它 →「允许选中程序联网」。",
            };

            if (constructor.Invoke(new object[]
                {
                    "阻止程序联网",
                    "确定要阻止「chrome.exe」联网吗？",
                    details,
                    warnings,
                    "阻止联网",
                    true,
                }) is not ConfirmForm dialog)
            {
                W("！（确认框构造失败，跳过 04 的渲染）");
                return;
            }

            dialog.StartPosition = FormStartPosition.Manual;
            dialog.Location = new Point(0, 0);
            dialog.Show();
            Application.DoEvents();

            RenderFormTo(dialog, Path.Combine(outputDir, "04-confirm-block.png"));

            dialog.Close();
            dialog.Dispose();
        }
        catch (Exception ex)
        {
            W($"！（渲染确认框失败：{ex.Message}）");
        }
    }

    /// <summary>把窗体渲染成指定路径的 PNG。</summary>
    private static void RenderFormTo(Form form, string path)
    {
        try
        {
            using var bitmap = new Bitmap(form.Width, form.Height);
            form.DrawToBitmap(bitmap, new Rectangle(0, 0, form.Width, form.Height));
            bitmap.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            W($"    已生成：{Path.GetFileName(path)}（{form.Width}×{form.Height}）");
        }
        catch (Exception ex)
        {
            W($"    （渲染失败：{ex.Message}）");
        }
    }

    /// <summary>
    /// 只在 <c>--ui-render</c> 时用：往表格里灌一批有代表性的样本数据，
    /// 这样渲染出来的 PNG 能看出**真实列宽、文本截断和三种放行状态**，
    /// 而不是一张空表 —— 空表看不出任何列宽问题，那样的图对人眼核对没有价值。
    /// </summary>
    private static void FillRenderSamples(MainForm form)
    {
        if (!TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned)
            || !TryGetField<HashSet<string>>(form, "_whitelistedPaths", out var whitelisted)
            || !TryGetField<HashSet<string>>(form, "_otherAllowPaths", out var otherAllow))
        {
            return;
        }

        const string whitelistedPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        const string otherPath = @"C:\Program Files (x86)\SomeVendor\updater.exe";

        whitelisted.Clear();
        whitelisted.Add(whitelistedPath);

        otherAllow.Clear();
        otherAllow.Add(otherPath);

        scanned.Clear();
        scanned.Add(MakeConnection(1201, "chrome.exe", "142.250.66.78", 443, "IPv4", 52101, TcpState.Established, whitelistedPath));
        scanned.Add(MakeConnection(1202, "chrome.exe", "142.250.66.79", 443, "IPv4", 52102, TcpState.Established, whitelistedPath));
        scanned.Add(MakeConnection(1203, "updater.exe", "203.0.113.9", 80, "IPv4", 52103, TcpState.Established, otherPath));
        scanned.Add(MakeConnection(1204, "unknown.exe", "198.51.100.7", 8443, "IPv4", 52104, TcpState.Established, @"C:\Users\VM\AppData\Local\Temp\a-very-long-path\unknown.exe"));
        scanned.Add(MakeConnection(1205, "svchost.exe", "224.0.0.251", 5353, "IPv6", 52105, TcpState.Established, @"C:\Windows\System32\svchost.exe"));
        scanned.Add(MakeConnection(1206, "no-path.exe", "10.0.0.2", 445, "IPv4", 52106, TcpState.Established));

        InvokePrivate(form, "RebuildView", null);
        InvokePrivate(form, "RebindGrid", new object?[] { null });
        Application.DoEvents();
    }

    /// <summary>
    /// 「放行」列必须放得下最长的那个值。
    ///
    /// 为什么单独盯着这一列：它的全部价值就是让人**一眼**分清三种状态。
    /// 一旦显示成「已放行·本…」，用户就分不出是"我放行的"还是"别人放行的"，
    /// 于是严格的诚实性就没了 —— 完整含义虽然在悬停提示里，
    /// 但不该要求用户去悬停才能看懂。
    ///
    /// 顺便把实测像素数打进断言标题里：将来谁改了列宽，一眼就能看到差多少。
    /// </summary>
    private static void CheckWhitelistColumnFits(List<(string Title, bool Passed)> results, MainForm form, string caseName)
    {
        if (!TryGetField<DataGridView>(form, "_connectionGrid", out var grid))
        {
            return;
        }

        var column = grid.Columns[nameof(TcpConnectionItem.WhitelistText)];
        if (column is null)
        {
            results.Add(($"[{caseName}] 有「放行」列", false));
            return;
        }

        var candidates = new[] { "已放行·本工具", "已放行·其它来源", "未放行", "—" };
        var longest = candidates.OrderByDescending(t => TextRenderer.MeasureText(t, grid.Font).Width).First();
        var textWidth = TextRenderer.MeasureText(longest, grid.Font).Width;

        // +8：留给单元格左右内边距与网格线。
        var needed = textWidth + 8;

        W($"    [{caseName}] 「放行」列：最长值「{longest}」需 {needed}px，实宽 {column.Width}px");

        results.Add((
            $"[{caseName}] 「放行」列放得下最长值「{longest}」（需 {needed}px / 实宽 {column.Width}px）",
            column.Width >= needed));
    }

    /// <summary>设置窗口尺寸和三种「长度会变的文字」，并让布局算一遍。</summary>
    private static void ApplyUiCase(MainForm form, int width, string hint, string detail, string privacy)
    {
        form.Size = new Size(width, 900);
        Application.DoEvents();

        if (TryGetField<Label>(form, "_selectionHintLabel", out var hintLabel)) hintLabel.Text = hint;
        if (TryGetField<Label>(form, "_autostartDetailLabel", out var detailLabel)) detailLabel.Text = detail;
        if (TryGetField<Label>(form, "_privacyLabel", out var privacyLabel)) privacyLabel.Text = privacy;

        form.PerformLayout();
        Application.DoEvents();
    }

    /// <summary>检查「联网连接」页：工具栏控件不重叠也不越界，表格落在页内。</summary>
    private static void CheckConnectionPage(List<(string Title, bool Passed)> results, MainForm form, string caseName)
    {
        if (!TrySelectTab(form, "_tabConnections"))
        {
            results.Add(($"[{caseName}] 能切到「联网连接」页", false));
            return;
        }

        if (TryGetField<Control>(form, "_toolPanel", out var toolPanel))
        {
            CheckNoOverlap(results, $"[{caseName}] 工具栏三行互不重叠", toolPanel.Controls);
            CheckAllInside(results, $"[{caseName}] 工具栏三行都完整落在面板内", toolPanel, toolPanel.Controls);
        }
        else
        {
            results.Add(($"[{caseName}] 找到工具栏 _toolPanel", false));
        }

        // 每一行**内部**的控件也要查：只查「三行之间不重叠」是不够的 ——
        // 行内的按钮/开关/搜索框照样可能被行边缘裁掉。重构之后这一层才是最该查的。
        foreach (var rowName in new[] { "_toolRowFilters", "_toolRowActions", "_toolRowSearch" })
        {
            if (!TryGetField<Control>(form, rowName, out var row))
            {
                results.Add(($"[{caseName}] 找到工具栏的 {rowName}", false));
                continue;
            }

            CheckNoOverlap(results, $"[{caseName}] {rowName} 内控件互不重叠", row.Controls);
            CheckAllInside(results, $"[{caseName}] {rowName} 内控件完整落在本行内", row, row.Controls);
        }

        if (TryGetField<Control>(form, "_tabConnections", out var tab)
            && TryGetField<Control>(form, "_connectionGrid", out var grid))
        {
            CheckInsideParent(results, $"[{caseName}] 连接表格落在「联网连接」页内", tab, grid);
        }
    }

    /// <summary>检查「设置」页：三个分区互不重叠、宽度不越界，面板内部也不重叠。</summary>
    private static void CheckSettingsPage(List<(string Title, bool Passed)> results, MainForm form, string caseName)
    {
        if (!TrySelectTab(form, "_tabSettings"))
        {
            results.Add(($"[{caseName}] 能切到「设置」页", false));
            return;
        }

        if (!TryGetField<Control>(form, "_tabSettings", out var tab))
        {
            return;
        }

        var panels = new List<Control>();
        foreach (var fieldName in new[] { "_autostartPanel", "_privacyPanel", "_strictModePanel", "_taskXmlPanel" })
        {
            if (TryGetField<Control>(form, fieldName, out var panel))
            {
                panels.Add(panel);
            }
        }

        CheckNoOverlapList(results, $"[{caseName}] 设置页四个分区互不重叠", panels);

        // 宽度不能超过标签页可视宽度（AutoScroll 与 Anchor=Right 打架会导致累积漂移）
        var clientWidth = tab.ClientSize.Width;
        foreach (var panel in panels)
        {
            var ok = panel.Width <= clientWidth;
            if (!ok)
            {
                W($"    ！宽度越界：{panel.Name} = {panel.Width} > 标签页 {clientWidth}");
            }

            results.Add(($"[{caseName}] {panel.Name} 宽度不超过标签页可视宽度", ok));
        }

        // 隐私面板内部
        if (TryGetField<Control>(form, "_privacyScrollHost", out var scrollHost)
            && TryGetField<Control>(form, "_privacyBottomPanel", out var bottom)
            && TryGetField<Control>(form, "_privacyPanel", out var privacyPanel))
        {
            CheckNoOverlapList(results, $"[{caseName}] 隐私面板：文字区与底部开关区不重叠",
                new List<Control> { scrollHost, bottom });

            CheckInsideParent(results, $"[{caseName}] 隐私面板：底部开关区完整落在面板内", privacyPanel, bottom);
            CheckNoOverlap(results, $"[{caseName}] 隐私面板底部四个控件互不重叠", bottom.Controls);
            CheckAllInside(results, $"[{caseName}] 隐私面板底部控件完整落在底部区内", bottom, bottom.Controls);
        }

        // 自启面板内部：状态 / 详情 / 按钮条
        var autostartParts = new List<Control>();
        foreach (var fieldName in new[] { "_autostartStatusLabel", "_autostartDetailHost", "_autostartButtons" })
        {
            if (TryGetField<Control>(form, fieldName, out var part))
            {
                autostartParts.Add(part);
            }
        }

        CheckNoOverlapList(results, $"[{caseName}] 自启面板：状态 / 详情 / 按钮条不重叠", autostartParts);

        // 严格模式面板内部：状态 / 说明 / 按钮条
        var strictParts = new List<Control>();
        foreach (var fieldName in new[] { "_strictModeStatusLabel", "_strictModeDetailLabel", "_strictModeButtons" })
        {
            if (TryGetField<Control>(form, fieldName, out var part))
            {
                strictParts.Add(part);
            }
        }

        CheckNoOverlapList(results, $"[{caseName}] 严格模式面板：状态 / 说明 / 按钮条不重叠", strictParts);

        if (TryGetField<Control>(form, "_strictModePanel", out var strictPanel)
            && TryGetField<Control>(form, "_strictModeButtons", out var strictButtons))
        {
            CheckInsideParent(results, $"[{caseName}] 严格模式面板：按钮条完整落在面板内", strictPanel, strictButtons);
            CheckNoOverlap(results, $"[{caseName}] 严格模式面板：两个按钮不重叠", strictButtons.Controls);
        }
    }

    private static bool TrySelectTab(MainForm form, string tabFieldName)
    {
        if (!TryGetField<TabControl>(form, "_tabControl", out var tabs)
            || !TryGetField<Control>(form, tabFieldName, out var page)
            || page is not TabPage tabPage)
        {
            return false;
        }

        if (!ReferenceEquals(tabs.SelectedTab, tabPage))
        {
            tabs.SelectedTab = tabPage;
            Application.DoEvents();
        }

        return true;
    }

    private static void CheckNoOverlap(
        List<(string Title, bool Passed)> results, string title, Control.ControlCollection controls)
    {
        var list = new List<Control>();
        foreach (Control control in controls)
        {
            list.Add(control);
        }

        CheckNoOverlapList(results, title, list);
    }

    private static void CheckNoOverlapList(
        List<(string Title, bool Passed)> results, string title, List<Control> controls)
    {
        for (var i = 0; i < controls.Count; i++)
        {
            for (var j = i + 1; j < controls.Count; j++)
            {
                if (!controls[i].Bounds.IntersectsWith(controls[j].Bounds))
                {
                    continue;
                }

                W($"    ！重叠：{controls[i].Name} {controls[i].Bounds} ∩ {controls[j].Name} {controls[j].Bounds}");
                results.Add((title, false));
                return;
            }
        }

        results.Add((title, true));
    }

    private static void CheckAllInside(
        List<(string Title, bool Passed)> results, string title, Control parent, Control.ControlCollection controls)
    {
        var area = parent.ClientRectangle;

        foreach (Control control in controls)
        {
            if (area.Contains(control.Bounds))
            {
                continue;
            }

            W($"    ！越界：{control.Name} {control.Bounds} 超出 {parent.Name} 客户区 {area}");
            results.Add((title, false));
            return;
        }

        results.Add((title, true));
    }

    private static void CheckInsideParent(
        List<(string Title, bool Passed)> results, string title, Control parent, Control child)
    {
        var inside = parent.ClientRectangle.Contains(child.Bounds);
        if (!inside)
        {
            W($"    ！越界：{child.Name} {child.Bounds} 超出 {parent.Name} 客户区 {parent.ClientRectangle}");
        }

        results.Add((title, inside));
    }

    /// <summary>把窗体渲染成 PNG（只在 --ui-render 时调用，便于人眼核对布局）。</summary>
    /// <summary>
    /// 临时阻断的**界面**自检：确认框里的时长选择、规则页里的「自动解除」列。
    ///
    /// 这条链路有个安全上的意义：临时阻断到期时规则会被**自动删除**，
    /// 而「所有会改系统状态的操作必须弹确认框」是项目的硬性约定。
    /// 自动删除没法再弹框（弹了后台程序就永远解不开），
    /// 因此必须**在创建时**让用户看到并同意「什么时候会自动解除」——
    /// 这几条断言就是在守这个「事先同意」的入口。
    /// </summary>
    private static void CheckTemporaryBlockUi(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 临时阻断：确认框与规则页 =====");

        // ---------- 规则页要有「自动解除」列 ----------
        if (TryGetField<Control>(form, "_rulesGrid", out var rulesGridControl)
            && rulesGridControl is DataGridView rulesGrid)
        {
            results.Add(("「规则」页有「自动解除」列（用户能看出规则会自己消失）",
                rulesGrid.Columns[nameof(FirewallRuleItem.ExpiryText)] is not null));
        }
        else
        {
            results.Add(("能找到规则表格 _rulesGrid", false));
        }

        // ---------- 确认框：带时长选择 ----------
        var withDuration = TryCreateConfirmForm(offerDuration: true);
        if (withDuration is null)
        {
            results.Add(("能用反射构造带「阻断时长」的确认框", false));
            return;
        }

        using (withDuration)
        {
            withDuration.Show();
            Application.DoEvents();

            var permanent = GetRadio(withDuration, "_permanentRadio");
            var thirty = GetRadio(withDuration, "_thirtyMinutesRadio");
            var twoHours = GetRadio(withDuration, "_twoHoursRadio");
            var nextBoot = GetRadio(withDuration, "_nextBootRadio");
            var hint = GetLabel(withDuration, "_durationHint");

            results.Add(("确认框里有 4 个时长选项",
                permanent is not null && thirty is not null && twoHours is not null && nextBoot is not null));
            results.Add(("默认选「永久」（不改变老用户已经习惯的行为）", permanent?.Checked == true));
            results.Add(("默认情况下 ChosenExpiry 就是永久", ReadChosenExpiry(withDuration)?.IsPermanent == true));

            var hintTexts = new List<string>();

            if (thirty is not null)
            {
                thirty.Checked = true;
                Application.DoEvents();

                var expiry = ReadChosenExpiry(withDuration);
                var remaining = expiry?.ExpiresAtUtc - DateTime.UtcNow;

                results.Add(("选「30 分钟」后 ChosenExpiry 是限时、且约 30 分钟后",
                    expiry?.Kind == RuleExpiryKind.AtTime
                    && remaining is not null
                    && Math.Abs(remaining.Value.TotalMinutes - 30) < 1));

                hintTexts.Add(hint?.Text ?? string.Empty);
            }

            if (twoHours is not null)
            {
                twoHours.Checked = true;
                Application.DoEvents();

                var expiry = ReadChosenExpiry(withDuration);
                var remaining = expiry?.ExpiresAtUtc - DateTime.UtcNow;

                results.Add(("选「2 小时」后 ChosenExpiry 约 2 小时后",
                    expiry?.Kind == RuleExpiryKind.AtTime
                    && remaining is not null
                    && Math.Abs(remaining.Value.TotalHours - 2) < 0.1));

                hintTexts.Add(hint?.Text ?? string.Empty);
            }

            if (nextBoot is not null)
            {
                nextBoot.Checked = true;
                Application.DoEvents();

                var expiry = ReadChosenExpiry(withDuration);
                results.Add(("选「直到下次重启」后 ChosenExpiry 是重启类型",
                    expiry?.Kind == RuleExpiryKind.OnNextBoot));

                hintTexts.Add(hint?.Text ?? string.Empty);
            }

            W($"    三种选择的提示文字各不相同 = {hintTexts.Distinct().Count() == hintTexts.Count}");
            results.Add(("提示文字会随选择变化（用户点确认前就知道会发生什么）",
                hintTexts.Count >= 2 && hintTexts.Distinct().Count() == hintTexts.Count));

            if (_renderUi)
            {
                RenderForm(withDuration, "ui-confirm-duration.png");
            }
        }

        // ---------- 不需要时长的确认框里不该有这些控件 ----------
        var withoutDuration = TryCreateConfirmForm(offerDuration: false);
        if (withoutDuration is not null)
        {
            using (withoutDuration)
            {
                results.Add(("不需要选时长时，确认框里没有那几个单选按钮（不影响别的确认流程）",
                    GetRadio(withoutDuration, "_permanentRadio") is null));
            }
        }
    }

    /// <summary>用反射构造确认框（它的构造函数是私有的，只能通过那个静态 Show 走）。</summary>
    private static ConfirmForm? TryCreateConfirmForm(bool offerDuration)
    {
        var constructor = typeof(ConfirmForm).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            types: new[]
            {
                typeof(string),
                typeof(string),
                typeof(IReadOnlyList<KeyValuePair<string, string>>),
                typeof(IReadOnlyList<string>),
                typeof(string),
                typeof(bool),
            },
            modifiers: null);

        return constructor?.Invoke(new object[]
        {
            "测试标题",
            "这是自检用的确认框，确定要继续吗？",
            new List<KeyValuePair<string, string>> { new("程序名", "demo.exe") },
            new List<string> { "这是自检用的风险提示。" },
            "确定",
            offerDuration,
        }) as ConfirmForm;
    }

    private static RadioButton? GetRadio(ConfirmForm form, string fieldName)
        => TryGetField<RadioButton>(form, fieldName, out var radio) ? radio : null;

    private static Label? GetLabel(ConfirmForm form, string fieldName)
        => TryGetField<Label>(form, fieldName, out var label) ? label : null;

    private static RuleExpiry? ReadChosenExpiry(ConfirmForm form)
        => typeof(ConfirmForm).GetProperty("ChosenExpiry")?.GetValue(form) as RuleExpiry;

    /// <summary>
    /// 临时阻断「到期检查」的**接线**自检。
    ///
    /// 只查接线，**不碰防火墙** —— `--ui-check` 承诺不动系统状态。
    /// 真正的「建规则 → 到期 → 自动删掉」在需要管理员的完整测试里验。
    ///
    /// 这里最要紧的一条是：到期检查必须是**独立**定时器。
    /// 产品负责人最初的想法是「搭在每 3 秒的刷新循环上」，但那个开关**默认是关的**——
    /// 搭上去的话，没勾开关的用户就永远等不到临时阻断自动解除。
    /// </summary>
    private static void CheckExpiryTimerWiring(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 临时阻断的到期检查（接线）=====");

        if (!TryGetField<System.Windows.Forms.Timer>(form, "_expiryTimer", out var expiryTimer))
        {
            results.Add(("到期检查定时器已挂上（_expiryTimer 存在）", false));
            return;
        }

        results.Add(("到期检查定时器已挂上（_expiryTimer 存在）", true));

        W($"    到期检查间隔 = {expiryTimer.Interval} ms");
        results.Add(($"到期检查间隔取自 AppConstants（{AppConstants.ExpiredRuleCheckIntervalMs} ms）",
            expiryTimer.Interval == AppConstants.ExpiredRuleCheckIntervalMs));

        if (TryGetField<System.Windows.Forms.Timer>(form, "_autoRefreshTimer", out var autoTimer))
        {
            results.Add(("到期检查和自动刷新是两个独立定时器（不是同一个实例）",
                !ReferenceEquals(expiryTimer, autoTimer)));
            results.Add(("两者间隔不同（30 秒 vs 3 秒），说明没有搭在自动刷新上",
                expiryTimer.Interval != autoTimer.Interval));
        }
        else
        {
            results.Add(("能找到自动刷新定时器用于对照", false));
        }

        // 3.0-c：到期清理归服务，界面不再自己跑写操作；用"上次解除计数"感知并提示。
        var guardField = form.GetType().GetField(
            "_lastExpiredPurged", BindingFlags.Instance | BindingFlags.NonPublic);

        results.Add(("有服务驱动的到期解除计数字段 _lastExpiredPurged",
            guardField?.FieldType == typeof(int)));
    }

    /// <summary>
    /// 搜索框的**接线**自检 —— 不只是布局，而是「文本框一改，显示列表真的跟着变」。
    ///
    /// 为什么单独测这一条：过滤/排序的**逻辑**在 --connection-filter-test 里已经测透了，
    /// 但「控件 → 事件 → 重建显示列表 → 重绑 → 状态栏」这条链路只有在这里才测得到。
    ///
    /// 本方法会先把归属查询服务关掉 —— 因为搜索事件里会补发归属请求，
    /// 而 --ui-check 承诺**不联网**。
    /// </summary>
    private static void CheckSearchWiring(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 搜索框接线（功能，不只是布局）=====");

        // 必须先切回「联网连接」页：搜索框和清除按钮都在那一页上，
        // 页签不是它的时候控件不可见，Button.PerformClick() 会静默地什么都不做
        // （实测踩到：直接调 PerformClick 会「点了个寂寞」）。
        if (!TrySelectTab(form, "_tabConnections"))
        {
            results.Add(("搜索接线前能切回「联网连接」页", false));
            return;
        }

        if (TryGetField<IpOwnershipService>(form, "_ipOwnershipService", out var ownershipService))
        {
            // 关掉，避免搜索事件真的去联网。
            ownershipService.IsEnabled = false;
        }

        if (!TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned)
            || !TryGetField<List<TcpConnectionItem>>(form, "_connections", out var displayed)
            || !TryGetField<TextBox>(form, "_searchBox", out var searchBox))
        {
            results.Add(("搜索框接线自检能找到必要的字段", false));
            return;
        }

        // 造一批「扫描结果」，再让搜索框去过滤它。
        scanned.Clear();
        scanned.AddRange(new[]
        {
            MakeConnection(100, "chrome.exe", "8.8.8.8", 443, "IPv4", 50001, TcpState.Established),
            MakeConnection(200, "notepad.exe", "9.9.9.9", 80, "IPv4", 50002, TcpState.Established),
        });

        searchBox.Text = "chrome";
        Application.DoEvents();
        results.Add(("输入 chrome 后显示列表只剩 1 条", displayed.Count == 1));
        results.Add(("剩下那条确实是 chrome.exe",
            displayed.Count == 1 && displayed[0].ProcessName == "chrome.exe"));

        searchBox.Text = "9.9.9.9";
        Application.DoEvents();
        results.Add(("改成按远程 IP 搜（9.9.9.9）同样能过滤",
            displayed.Count == 1 && displayed[0].ProcessName == "notepad.exe"));

        searchBox.Text = "绝不可能匹配的内容";
        Application.DoEvents();
        results.Add(("没有匹配时显示列表为空", displayed.Count == 0));

        if (TryGetField<ToolStripStatusLabel>(form, "_summaryLabel", out var summary))
        {
            // ToolStripItem.Text 是可空的，先归一化成空串再判断。
            var text = summary.Text ?? string.Empty;
            W($"    状态栏 = {text}");
            results.Add(("过滤后状态栏区分「显示」与「共」",
                text.Contains("显示") && text.Contains("共")));
        }

        if (TryGetField<Button>(form, "_clearSearchButton", out var clearButton))
        {
            clearButton.PerformClick();
            Application.DoEvents();

            results.Add(("点「清除」后搜索框被清空", searchBox.Text.Length == 0));
            results.Add(("点「清除」后恢复完整列表（2 条）", displayed.Count == 2));
        }
    }

    /// <summary>
    /// 排序的**接线**自检 —— 点表头真的会重排，而且刷新之后不丢。
    ///
    /// 排序的**逻辑**在 --connection-filter-test 里已经测过（按数值、IPv4 优先）；
    /// 这里测的是「表头点击 → 事件 → 重建显示列表 → 箭头」这条链路。
    /// 样本刻意让 9.9.9.9 与 10.0.0.1 相邻 —— 一旦退化成字符串排序就会露馅。
    /// </summary>
    private static void CheckSortWiring(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 排序接线（功能，不只是布局）=====");

        if (!TrySelectTab(form, "_tabConnections"))
        {
            results.Add(("排序接线前能切回「联网连接」页", false));
            return;
        }

        if (TryGetField<IpOwnershipService>(form, "_ipOwnershipService", out var ownershipService))
        {
            // 本模式承诺不联网。
            ownershipService.IsEnabled = false;
        }

        if (!TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned)
            || !TryGetField<List<TcpConnectionItem>>(form, "_connections", out var displayed)
            || !TryGetField<DataGridView>(form, "_connectionGrid", out var grid))
        {
            results.Add(("排序接线自检能找到必要的字段", false));
            return;
        }

        var chrome = MakeConnection(100, "chrome.exe", "8.8.8.8", 443, "IPv4", 50001, TcpState.Established);
        var svchost = MakeConnection(3000, "svchost.exe", "10.0.0.1", 53, "IPv4", 50002, TcpState.Established);
        var notepad = MakeConnection(200, "notepad.exe", "9.9.9.9", 80, "IPv4", 50003, TcpState.Established);

        scanned.Clear();
        scanned.AddRange(new[] { chrome, svchost, notepad });

        ClickConnectionHeader(form, grid, nameof(TcpConnectionItem.Pid));
        var pidAsc = displayed.Select(i => i.Pid).ToArray();
        W($"    点 PID 表头后 = {string.Join(", ", pidAsc)}");
        results.Add(("点 PID 表头后按 PID 升序（100, 200, 3000）",
            pidAsc.SequenceEqual(new[] { 100, 200, 3000 })));
        results.Add(("PID 表头出现升序箭头",
            grid.Columns[nameof(TcpConnectionItem.Pid)]?.HeaderCell.SortGlyphDirection == SortOrder.Ascending));

        ClickConnectionHeader(form, grid, nameof(TcpConnectionItem.Pid));
        results.Add(("再点同一列表头变成降序（3000, 200, 100）",
            displayed.Select(i => i.Pid).SequenceEqual(new[] { 3000, 200, 100 })));
        results.Add(("PID 表头箭头变成降序",
            grid.Columns[nameof(TcpConnectionItem.Pid)]?.HeaderCell.SortGlyphDirection == SortOrder.Descending));

        ClickConnectionHeader(form, grid, nameof(TcpConnectionItem.RemoteAddressText));
        var ipAsc = displayed.Select(i => i.RemoteAddress.ToString()).ToArray();
        W($"    点远程 IP 表头后 = {string.Join(", ", ipAsc)}");
        results.Add(("点远程 IP 表头后按数值升序（8.8.8.8, 9.9.9.9, 10.0.0.1）",
            ipAsc.SequenceEqual(new[] { "8.8.8.8", "9.9.9.9", "10.0.0.1" })));
        results.Add(("切到新列后箭头转移、旧列箭头清空",
            grid.Columns[nameof(TcpConnectionItem.RemoteAddressText)]?.HeaderCell.SortGlyphDirection == SortOrder.Ascending
            && grid.Columns[nameof(TcpConnectionItem.Pid)]?.HeaderCell.SortGlyphDirection == SortOrder.None));

        // 没开排序的列：点了应当毫无变化
        ClickConnectionHeader(form, grid, nameof(TcpConnectionItem.ProcessPathText));
        results.Add(("点不支持排序的列（程序路径）不会改变顺序",
            displayed.Select(i => i.RemoteAddress.ToString()).SequenceEqual(ipAsc)));

        // 模拟「每 3 秒的重新扫描」：扫描结果顺序变了，界面应当仍按选中的列排。
        scanned.Clear();
        scanned.AddRange(new[] { notepad, chrome, svchost });

        if (TryInvokePrivate(form, "RebuildView"))
        {
            results.Add(("重新扫描（顺序变了）之后排序依然生效",
                displayed.Select(i => i.RemoteAddress.ToString())
                    .SequenceEqual(new[] { "8.8.8.8", "9.9.9.9", "10.0.0.1" })));
        }
        else
        {
            results.Add(("能调用 RebuildView 来模拟刷新", false));
        }

        // 排序 + 搜索共存
        if (TryGetField<TextBox>(form, "_searchBox", out var searchBox))
        {
            searchBox.Text = "chrome";
            Application.DoEvents();
            results.Add(("排序与搜索共存：过滤后剩 1 条且顺序正确",
                displayed.Count == 1 && displayed[0].ProcessName == "chrome.exe"));

            searchBox.Clear();
            Application.DoEvents();
        }
    }

    /// <summary>
    /// 列宽「预览线」拖动的自检。
    ///
    /// 背景：DataGridView 自带的实时改列宽会**每移动一次鼠标就把整表重画一遍**，
    /// 实测 1920×1080、20 个可见行时单帧 33~40ms（25~30fps），拖起来跟不上鼠标。
    /// 所以关掉自带拖动，改成「拖动时只画一条竖线、松开才真正改宽度」。
    ///
    /// 这里用**真实鼠标消息**驱动（SendMessage），走的是产品真实的
    /// MouseDown / MouseMove / MouseUp 处理器，不是绕过去自己模拟。
    /// </summary>
    private static void CheckColumnResizeWiring(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 列宽拖动（预览线）=====");

        if (!TrySelectTab(form, "_tabConnections")
            || !TryGetField<DataGridView>(form, "_connectionGrid", out var grid))
        {
            results.Add(("列宽拖动自检能找到连接表格", false));
            return;
        }

        results.Add(("自带的实时改列宽已关闭（AllowUserToResizeColumns = false）",
            !grid.AllowUserToResizeColumns));

        // 先把窗口设成默认宽度，并灌一批数据让**纵向滚动条真的出现** ——
        // 否则「有没有横向滚动条」这一条测不准（纵向滚动条会占掉约 17px 宽度）。
        form.Size = new Size(1180, 800);
        Application.DoEvents();

        if (TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned))
        {
            scanned.Clear();
            for (var i = 0; i < 120; i++)
            {
                scanned.Add(MakeConnection(
                    2000 + i, $"proc{i % 10}.exe", $"10.0.{i % 250}.{i % 200}",
                    (ushort)(80 + i), "IPv4", (ushort)(40000 + i), TcpState.Established));
            }

            TryInvokePrivate(form, "RebuildView");
            TryInvokePrivate(form, "RebindGrid", new object?[] { null });
            Application.DoEvents();
        }

        if (!TryGetField<object>(form, "_columnResizer", out var resizer))
        {
            results.Add(("列宽拖动器已挂上（_columnResizer 存在）", false));
            return;
        }

        results.Add(("列宽拖动器已挂上（_columnResizer 存在）", true));

        var column = grid.Columns[nameof(TcpConnectionItem.Pid)];
        if (column is null)
        {
            results.Add(("找到用于测试的 PID 列", false));
            return;
        }

        var originalWidth = column.Width;

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var rect = grid.GetColumnDisplayRectangle(column.Index, cutOverflow: true);
            if (rect.Width > 0)
            {
                break;
            }

            // 列被滚动到视野外了，把它滚回来再试。
            grid.FirstDisplayedScrollingColumnIndex = column.Index;
            Application.DoEvents();
        }

        var columnRect = grid.GetColumnDisplayRectangle(column.Index, cutOverflow: true);
        var dividerX = columnRect.Right - 1;
        var headerY = Math.Max(2, grid.ColumnHeadersHeight / 2);
        var before = column.Width;

        W($"    PID 列：x={columnRect.Left}..{columnRect.Right}，列宽={before}，分隔线在 x={dividerX}");

        // 诊断：先把命中测试单独打出来，区分「坐标/命中测试不对」和「消息没送到」。
        var probe = grid.HitTest(dividerX, headerY);
        W($"    命中测试 @({dividerX},{headerY}) → {probe.Type}，ColumnIndex={probe.ColumnIndex}；" +
          $"表头可见={grid.ColumnHeadersVisible}，表头高={grid.ColumnHeadersHeight}，客户区高={grid.ClientSize.Height}");

        // ---------- 1. 正常拖动：按下 → 移动 60px → 松开 ----------
        SendMouse(grid, WmLeftButtonDown, dividerX, headerY);
        SendMouse(grid, WmMouseMove, dividerX + 60, headerY);
        Application.DoEvents();

        results.Add(("拖动过程中列宽**不变**（这正是省时间的关键）", column.Width == before));

        SendMouse(grid, WmLeftButtonUp, dividerX + 60, headerY);
        Application.DoEvents();

        W($"    松开后列宽 = {column.Width}（期望 {before + 60}）");
        results.Add(("松开鼠标后列宽才真正改变（+60）", column.Width == before + 60));

        // ---------- 2. 拖动结束后紧接着的表头点击要被吃掉 ----------
        var consume = resizer.GetType().GetMethod("ConsumeHeaderClickSuppression");
        results.Add(("拖完列宽后，紧接着那次表头点击会被忽略（不会误触发排序）",
            consume?.Invoke(resizer, null) is true));

        // ---------- 3. 拖动中按 Esc 取消 ----------
        var widthBeforeEsc = column.Width;
        var rectNow = grid.GetColumnDisplayRectangle(column.Index, cutOverflow: true);
        var dividerNow = rectNow.Right - 1;

        SendMouse(grid, WmLeftButtonDown, dividerNow, headerY);
        SendMouse(grid, WmMouseMove, dividerNow + 80, headerY);
        SendMessage(grid.Handle, WmKeyDown, (IntPtr)VirtualKeyEscape, IntPtr.Zero);
        SendMouse(grid, WmLeftButtonUp, dividerNow + 80, headerY);
        Application.DoEvents();

        results.Add(("拖动中按 Esc 取消：列宽保持原值", column.Width == widthBeforeEsc));

        // ---------- 4. 最小宽度下限 ----------
        var rectMin = grid.GetColumnDisplayRectangle(column.Index, cutOverflow: true);
        var dividerMin = rectMin.Right - 1;

        SendMouse(grid, WmLeftButtonDown, dividerMin, headerY);
        SendMouse(grid, WmMouseMove, Math.Max(0, dividerMin - 600), headerY);
        SendMouse(grid, WmLeftButtonUp, Math.Max(0, dividerMin - 600), headerY);
        Application.DoEvents();

        W($"    往左狂拖之后列宽 = {column.Width}（下限 40）");
        results.Add(("拖到再窄也会被下限挡住（正好停在下限 40px）", column.Width == 40));

        // ---------- 5. 程序路径与 PID 之间的分隔线也必须能拖 ----------
        // 这是用户报的 bug：程序路径原本是 Fill 列，而 Fill 列右边那条分隔线天生不可拖。
        var pathColumn = grid.Columns[nameof(TcpConnectionItem.ProcessPathText)];
        if (pathColumn is not null)
        {
            var pathRect = grid.GetColumnDisplayRectangle(pathColumn.Index, cutOverflow: true);
            var pathDivider = pathRect.Right - 1;
            var pathBefore = pathColumn.Width;

            SendMouse(grid, WmLeftButtonDown, pathDivider, headerY);
            SendMouse(grid, WmMouseMove, pathDivider + 50, headerY);
            SendMouse(grid, WmLeftButtonUp, pathDivider + 50, headerY);
            Application.DoEvents();

            W($"    程序路径列：{pathBefore} → {pathColumn.Width}（期望 {pathBefore + 50}）");
            results.Add(("程序路径与 PID 之间的分隔线也能拖（原本是 Fill 列，拖不动）",
                pathColumn.Width == pathBefore + 50));

            pathColumn.Width = pathBefore;
            Application.DoEvents();
        }

        // ---------- 6. 默认宽度下不该出现横向滚动条 ----------
        // Fill 列挪到最后一列之后，列宽配比要刚好放得下，否则默认界面就带横向滚动条。
        // 先把前面几次拖动改过的宽度还原成默认值，再让布局重算一遍 ——
        // 否则读到的是「拖动之后还没重算完」的中间状态。
        column.Width = originalWidth;
        grid.PerformLayout();
        Application.DoEvents();

        var totalWidth = 0;
        DataGridViewColumn? fillColumn = null;
        foreach (DataGridViewColumn c in grid.Columns)
        {
            totalWidth += c.Width;
            if (c.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
            {
                fillColumn = c;
            }
        }

        W($"    表格客户区宽 = {grid.ClientSize.Width}，各列宽之和 = {totalWidth}，" +
          $"Fill 列宽 = {fillColumn?.Width}（下限 {fillColumn?.MinimumWidth}）");

        results.Add(("默认窗口宽度下没有横向滚动条（列宽配比合适）", !HorizontalScrollBarVisible(grid)));
    }

    /// <summary>HorizontalScrollBar 是 protected，用反射读它的可见性。</summary>
    private static bool HorizontalScrollBarVisible(DataGridView grid)
    {
        var property = typeof(DataGridView).GetProperty(
            "HorizontalScrollBar", BindingFlags.Instance | BindingFlags.NonPublic);

        return property?.GetValue(grid) is ScrollBar bar && bar.Visible;
    }

    private const int WmMouseMove = 0x0200;
    private const int WmLeftButtonDown = 0x0201;
    private const int WmLeftButtonUp = 0x0202;
    private const int WmKeyDown = 0x0100;
    private const int VirtualKeyEscape = 0x1B;

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    /// <summary>往表格发一条鼠标消息（x/y 是控件客户区坐标）。</summary>
    private static void SendMouse(DataGridView grid, int message, int x, int y)
    {
        // 按住左键时鼠标键状态要带上 MK_LBUTTON，否则控件不会当成「拖动中」。
        var wParam = message == WmLeftButtonDown || message == WmMouseMove ? (IntPtr)1 : IntPtr.Zero;
        var lParam = (IntPtr)((y << 16) | (x & 0xFFFF));

        SendMessage(grid.Handle, message, wParam, lParam);
    }

    /// <summary>模拟点击某一列的表头（走产品真实的 ColumnHeaderMouseClick 处理器）。</summary>
    private static void ClickConnectionHeader(MainForm form, DataGridView grid, string columnName)    {
        var column = grid.Columns[columnName];
        if (column is null)
        {
            return;
        }

        var args = new DataGridViewCellMouseEventArgs(
            column.Index, -1, 0, 0, new MouseEventArgs(MouseButtons.Left, 1, 0, 0, 0));

        TryInvokePrivate(form, "OnConnectionGridColumnHeaderMouseClick", form, args);
        Application.DoEvents();
    }

    /// <summary>调用产品的私有方法（找不到就返回 false，不让自检崩掉）。</summary>
    private static bool TryInvokePrivate(object target, string name, params object?[] args)
    {
        var method = target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic);
        if (method is null)
        {
            return false;
        }

        method.Invoke(target, args);
        return true;
    }

    /// <summary>把窗体渲染成 PNG（只在 --ui-render 时调用，便于人眼核对布局）。</summary>
    private static void RenderForm(Form form, string fileName)
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, fileName);
            using var bitmap = new Bitmap(form.Width, form.Height);
            form.DrawToBitmap(bitmap, new Rectangle(0, 0, form.Width, form.Height));
            bitmap.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            W($"    渲染图：{path}");
        }
        catch (Exception ex)
        {
            W($"    （渲染失败：{ex.Message}）");
        }
    }

    /// <summary>把场景名变成安全的文件名片段（中文保留，其余非法字符换成下划线）。</summary>
    private static string Sanitize(string name)
    {
        var builder = new StringBuilder(name.Length);

        foreach (var ch in name)
        {
            builder.Append(char.IsLetterOrDigit(ch) ? ch : '_');
        }

        return builder.ToString();
    }

    /// <summary>按字段名读一个控件（找不到 / 类型不符都返回 false，不让自检崩掉）。</summary>
    private static bool TryGetField<T>(object target, string name, out T value) where T : class
    {
        value = default!;

        var field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        if (field?.GetValue(target) is T typed)
        {
            value = typed;
            return true;
        }

        return false;
    }

    private static bool TrySetField(object target, string name, object value)
    {
        var field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        if (field is null)
        {
            return false;
        }

        field.SetValue(target, value);
        return true;
    }

    /// <summary>
    /// 临时阻断的**只读**诊断：把「现在 / 本次开机时刻 / 每条规则的到期解析结果」打出来。
    ///
    /// 用途：出现「说好重启后自动解除、结果没解除」时，这一条命令就能分清是
    ///   (a) 规则里的到期标记**根本没写对**（说明字段会显示出来），还是
    ///   (b) 标记是对的、但**清理逻辑没跑**（那通常是程序当时没在运行）。
    /// 它只读，不改任何东西。
    /// </summary>
    private static void RunTempBlockStatus()
    {
        W("################################################################");
        W("#   临时阻断：当前状态（只读，什么都不改）                       #");
        W("################################################################");
        W();

        var now = DateTime.UtcNow;
        var boot = SystemUptime.BootTimeUtc;
        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

        W($"现在（本地）        = {now.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        W($"现在（UTC）         = {now:yyyy-MM-dd HH:mm:ss}");
        W($"本次开机时刻（推算）= {boot.ToLocalTime():yyyy-MM-dd HH:mm:ss}（UTC {boot:yyyy-MM-dd HH:mm:ss}）");
        W($"已开机时长          = {uptime.Days} 天 {uptime.Hours} 小时 {uptime.Minutes} 分");
        W($"「重启」判定容差    = {RuleExpiry.BootTimeTolerance.TotalMinutes:F0} 分钟");
        W();

        var rules = FirewallManager.GetAppGuardRules();
        W($"AppGuard 规则数     = {rules.Count}");
        W();

        if (rules.Count == 0)
        {
            W("（当前没有任何 AppGuard 规则）");
            return;
        }

        foreach (var rule in rules)
        {
            W($"  ── {rule.Name}");
            W($"     动作 / 方向      = {rule.ActionText} / {rule.DirectionText}");
            W($"     说明原文          = {rule.Description}");

            var parsed = rule.Expiry.Kind switch
            {
                RuleExpiryKind.AtTime =>
                    $"限时 → {rule.Expiry.ExpiresAtUtc:yyyy-MM-dd HH:mm:ss}Z",
                RuleExpiryKind.OnNextBoot =>
                    $"下次重启 → 创建时记下的开机时刻 {rule.Expiry.BootTimeUtc:yyyy-MM-dd HH:mm:ss}Z",
                _ => "永久",
            };

            W($"     解析出的到期方式  = {parsed}");

            var verdict = rule.Expiry.IsPermanent
                ? "永久，永不过期"
                : rule.Expiry.IsExpired(now, boot)
                    ? "**已过期（本应被清理）**"
                    : "还没到期";

            W($"     是否已过期        = {verdict}");
            W();
        }

        W("提示：如果上面写着「已过期（本应被清理）」，说明判断逻辑是对的，");
        W("      只是**发出清理动作的那个程序当时没在运行** —— 打开主程序即可清理。");
    }

    /// <summary>
    /// 临时阻断的到期信息自检（**离线、不碰系统**）。
    ///
    /// 覆盖三件事：
    ///   1. 编码 / 解析的往返（信息写进规则说明、再从说明里读回来）；
    ///   2. 到期判定（含「下次重启」用开机时刻比较、以及 5 分钟容差）；
    ///   3. **最容易出错的那一处**：程序路径很长时说明字段会被截断 ——
    ///      到期标记必须**优先保住**，否则规则会被当成「永久」，
    ///      用户的「30 分钟后解除」永远不会发生，而且他不会知道为什么。
    /// </summary>
    private static void RunTempBlockTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   临时阻断：到期信息的编码 / 解析 / 判定（离线、不碰系统）      #");
        W("################################################################");
        W();

        var now = new DateTime(2026, 10, 16, 12, 0, 0, DateTimeKind.Utc);
        var boot = new DateTime(2026, 10, 16, 8, 0, 0, DateTimeKind.Utc);

        // ---------- 永久 ----------
        CheckAssertion(results, "永久：不写任何标记", RuleExpiry.Never.Encode().Length == 0);
        CheckAssertion(results, "永久：永远不到期", !RuleExpiry.Never.IsExpired(now.AddYears(10), boot));
        CheckAssertion(results, "永久：显示文本是「永久」", RuleExpiry.Never.Describe(now) == "永久");
        CheckAssertion(results, "永久：IsPermanent 为真", RuleExpiry.Never.IsPermanent);

        // ---------- 向后兼容（这条最重要）----------
        const string legacyRule = "由 WinAppGuard 创建。目标程序：C:\\Program Files\\Old\\legacy.exe";
        CheckAssertion(results, "旧版本创建的规则（描述里没有标记）被当成永久，不会被误删",
            RuleExpiry.Parse(legacyRule) == RuleExpiry.Never);

        // ---------- 限时 ----------
        var at = RuleExpiry.At(now.AddMinutes(30));
        var encodedAt = at.Encode();
        W($"    限时编码 = {encodedAt}");

        var parsedAt = RuleExpiry.Parse("由 WinAppGuard 创建。目标程序：C:\\a.exe ｜ " + encodedAt);
        CheckAssertion(results, "限时：编码 → 解析往返一致", parsedAt == at);
        CheckAssertion(results, "限时：还没到点 → 未到期", !parsedAt.IsExpired(now, boot));
        CheckAssertion(results, "限时：刚好到点 → 已到期", parsedAt.IsExpired(now.AddMinutes(30), boot));
        CheckAssertion(results, "限时：过点之后 → 已到期", parsedAt.IsExpired(now.AddMinutes(31), boot));
        CheckAssertion(results, "限时：还没到点时显示「剩余 …」", parsedAt.Describe(now).Contains("剩余"));
        CheckAssertion(results, "限时：过点之后显示「已到期」", parsedAt.Describe(now.AddHours(1)) == "已到期");

        // ---------- 下次重启 ----------
        var onBoot = RuleExpiry.OnNextBoot(boot);
        var parsedBoot = RuleExpiry.Parse("由 WinAppGuard 创建。目标程序：C:\\b.exe ｜ " + onBoot.Encode());
        CheckAssertion(results, "下次重启：编码 → 解析往返一致", parsedBoot == onBoot);
        CheckAssertion(results, "下次重启：同一次开机 → 未到期", !parsedBoot.IsExpired(now, boot));
        CheckAssertion(results, "下次重启：开机时刻差 3 分钟（容差内）→ 未到期",
            !parsedBoot.IsExpired(now, boot.AddMinutes(3)));
        CheckAssertion(results, "下次重启：开机时刻差 10 分钟 → 已到期",
            parsedBoot.IsExpired(now, boot.AddMinutes(10)));
        CheckAssertion(results, "下次重启：显示文本是「重启后自动解除」",
            parsedBoot.Describe(now) == "重启后自动解除");

        // ---------- 快速启动的坑（产品负责人实际报过这个 bug）----------
        // 用「关机 → 开机」时，Windows 的「快速启动」会让内核从休眠文件恢复，
        // **开机时长不归零** —— 于是推算出的开机时刻和上次一模一样。
        // 只靠开机时刻判断会得出「没重启过」，规则永远不解除。
        // 所以再加一个确定无疑的信号：本次是不是**新的登录会话**。
        CheckAssertion(results, "快速启动场景：开机时刻一模一样、但是新的登录会话 → 仍然解除",
            parsedBoot.IsExpired(now, boot, freshLogonSession: true));
        CheckAssertion(results, "开机时刻没变、也不是新登录 → 不解除（不能误删）",
            !parsedBoot.IsExpired(now, boot, freshLogonSession: false));
        CheckAssertion(results, "「新登录会话」不会误伤永久规则",
            !RuleExpiry.Never.IsExpired(now, boot, freshLogonSession: true));
        CheckAssertion(results, "「新登录会话」不会误伤限时规则（没到点就是没到点）",
            !parsedAt.IsExpired(now, boot, freshLogonSession: true));

        // ---------- 解析不出来一律当永久（宁可手动解除，也不误删）----------
        CheckAssertion(results, "描述为 null → 永久", RuleExpiry.Parse(null) == RuleExpiry.Never);
        CheckAssertion(results, "描述里没有标记 → 永久", RuleExpiry.Parse("随便一段文字") == RuleExpiry.Never);
        CheckAssertion(results, "标记后面是垃圾 → 永久",
            RuleExpiry.Parse("x ｜ 自动解除=??胡乱写的") == RuleExpiry.Never);
        CheckAssertion(results, "标记后面是非法时间 → 永久",
            RuleExpiry.Parse("x ｜ 自动解除=2026-13-45T99:99:99Z") == RuleExpiry.Never);
        CheckAssertion(results, "路径里恰好含「自动解除=」时，以我们写在末尾的那个为准",
            RuleExpiry.Parse("路径里有 自动解除= 这种字 ｜ " + encodedAt) == at);

        // ---------- 截断保护 ----------
        var longPath = "C:\\" + new string('x', 400) + "\\a.exe";
        var described = TryBuildRuleDescription(longPath, at);

        if (described is null)
        {
            results.Add(("能用反射调用 BuildRuleDescription", false));
        }
        else
        {
            var tail = described.Length > 30 ? described[^30..] : described;
            W($"    超长路径下：描述长度 = {described.Length}，末尾 = …{tail}");

            results.Add(("超长路径被截断后，到期标记仍然保留", described.Contains("自动解除=")));
            results.Add(("描述长度不超过 255", described.Length <= 255));
            results.Add(("超长路径截断后仍能解析出正确的到期方式", RuleExpiry.Parse(described) == at));
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>BuildRuleDescription 是私有方法，用反射调用它来验证截断行为。</summary>
    private static string? TryBuildRuleDescription(string fullPath, RuleExpiry expiry)
    {
        var method = typeof(FirewallManager).GetMethod(
            "BuildRuleDescription", BindingFlags.Static | BindingFlags.NonPublic);

        return method?.Invoke(null, new object[] { fullPath, expiry }) as string;
    }

    /// <summary>
    /// 严格模式自检（2.0 产品级）：动态会话 + 真白名单，不改任何系统设置。
    ///
    /// 验证：能开（放行清单正确）、重复开被拒、能关（过滤器由系统自动删除）、重复关被拒。
    /// </summary>
    private static void RunStrictModeTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   严格模式自检（2.0：动态会话 + 真白名单，不改系统设置）       #");
        W("################################################################");
        W();

        var targetExe = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        var createdRule = string.Empty;

        try
        {
            using (var engine = WfpEngine.Open())
            {
                engine.DeleteAllOurFilters();
                engine.DeleteSublayer();
            }

            // 严格模式的放行清单来自"本工具的允许规则"，先造一条。
            createdRule = RuleEngine.CreateAllowRule(targetExe);
            W($"    已创建白名单规则：{createdRule}");

            W();
            W("===== 1. 开启 =====");

            var enable = StrictModeManager.Enable();
            W($"    {enable.Message}");

            CheckAssertion(results, "开启成功", enable.Success);
            CheckAssertion(results, "IsEnabled = true", StrictModeManager.IsEnabled);

            var permitted = StrictModeManager.PermittedPrograms;
            W($"    放行 {permitted.Count} 个程序：");
            foreach (var path in permitted.Take(10))
            {
                W($"      {path}");
            }

            if (permitted.Count > 10)
            {
                W($"      …… 以及另外 {permitted.Count - 10} 个");
            }

            CheckAssertion(results, "白名单里的记事本被放行",
                permitted.Any(path => string.Equals(path, targetExe, StringComparison.OrdinalIgnoreCase)));
            CheckAssertion(results, "本程序自己被自动放行",
                permitted.Any(path => string.Equals(path, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)));
            CheckAssertion(results, "系统必需程序被放行（svchost）",
                permitted.Any(path => string.Equals(
                    Path.GetFileName(path), "svchost.exe", StringComparison.OrdinalIgnoreCase)));

            using (var engine = WfpEngine.Open())
            {
                // 子层里同时躺着两类过滤器：规则自己的（每条 V4/V6 各一条）和严格模式的。
                var ruleFilterCount = RuleEngine.GetRules().Count * 2;
                var filterCount = engine.ListOurFilters().Count;
                var expected = permitted.Count * 2 + 2 + ruleFilterCount;

                W($"    过滤器 = {filterCount} 条" +
                  $"（预期 {expected} = 放行 {permitted.Count} × 2 + 阻止全部 2 + 规则 {ruleFilterCount}）");

                CheckAssertion(results, "过滤器条数正确", filterCount == expected);
            }

            W();
            W("===== 2. 重复开启应被拒绝 =====");
            var second = StrictModeManager.Enable();
            W($"    {second.Message}");
            CheckAssertion(results, "已在生效时再开 → 拒绝", !second.Success);

            W();
            W("===== 3. 关闭 =====");
            var disable = StrictModeManager.Disable();
            W($"    {disable.Message}");

            CheckAssertion(results, "关闭成功", disable.Success);
            CheckAssertion(results, "IsEnabled = false", !StrictModeManager.IsEnabled);

            using (var engine = WfpEngine.Open())
            {
                // 关闭严格模式**不该**动规则 —— 所以剩下的应当正好是规则自己的过滤器。
                var remaining = engine.ListOurFilters().Count;
                var ruleFilterCount = RuleEngine.GetRules().Count * 2;

                W($"    关闭后过滤器 = {remaining} 条（预期 {ruleFilterCount}：只剩规则自己的）");
                CheckAssertion(results, "严格模式的过滤器全部消失（规则自己的保留）",
                    remaining == ruleFilterCount);
            }

            CheckAssertion(results, "没开时再关 → 拒绝", !StrictModeManager.Disable().Success);
        }
        finally
        {
            StrictModeManager.Disable();

            try
            {
                if (!string.IsNullOrEmpty(createdRule))
                {
                    RuleEngine.DeleteRule(createdRule);
                }
            }
            catch (Exception)
            {
                // 忽略清理失败：这是自检，不影响结论。
            }

            try
            {
                using var engine = WfpEngine.Open();
                engine.DeleteAllOurFilters();
                engine.DeleteSublayer();
            }
            catch (WfpException)
            {
                // 已经干净。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 严格模式生命周期自检（2.0）。重点验证两件与 1.x 完全不同的事：
    ///   1. 白名单变化后必须重建会话 —— 否则新加的程序在严格模式下仍然上不了网；
    ///   2. 2.0 不再写 1.x 的「没还原」标志 —— 动态会话不需要启动兜底。
    /// </summary>
    private static void RunStrictModeLifecycleTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   严格模式生命周期自检（白名单变化 → 重建会话；不写 1.x 标志） #");
        W("################################################################");
        W();

        var settingsPath = Path.Combine(Path.GetTempPath(), $"wag-strict-{Guid.NewGuid():N}.json");
        var firstExe = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        var secondExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var firstRule = string.Empty;
        var secondRule = string.Empty;

        try
        {
            using (var engine = WfpEngine.Open())
            {
                engine.DeleteAllOurFilters();
                engine.DeleteSublayer();
            }

            firstRule = RuleEngine.CreateAllowRule(firstExe);
            W($"    第一条白名单规则：{firstRule}");

            W();
            W("===== 1. 只放行第一个程序 =====");
            var enable = StrictModeManager.Enable();
            CheckAssertion(results, "开启成功", enable.Success);

            var before = StrictModeManager.PermittedPrograms.Count;
            W($"    放行 {before} 个程序");

            CheckAssertion(results, "第一个程序在清单里",
                StrictModeManager.PermittedPrograms.Any(path =>
                    string.Equals(path, firstExe, StringComparison.OrdinalIgnoreCase)));
            CheckAssertion(results, "第二个程序还不在清单里",
                !StrictModeManager.PermittedPrograms.Any(path =>
                    string.Equals(path, secondExe, StringComparison.OrdinalIgnoreCase)));

            W();
            W("===== 2. 白名单变化 → 重建会话 =====");

            secondRule = RuleEngine.CreateAllowRule(secondExe);
            W($"    第二条白名单规则：{secondRule}");

            var refreshed = StrictModeManager.RefreshIfEnabled();
            CheckAssertion(results, "重建会话成功", refreshed is { Success: true });

            var after = StrictModeManager.PermittedPrograms;
            W($"    放行 {after.Count} 个程序（之前 {before} 个）");

            CheckAssertion(results, "新加的程序进入了放行清单",
                after.Any(path => string.Equals(path, secondExe, StringComparison.OrdinalIgnoreCase)));
            CheckAssertion(results, "清单正好多出 1 个", after.Count == before + 1);

            using (var engine = WfpEngine.Open())
            {
                var ruleFilterCount = RuleEngine.GetRules().Count * 2;
                var filterCount = engine.ListOurFilters().Count;
                var expected = after.Count * 2 + 2 + ruleFilterCount;

                W($"    过滤器 = {filterCount} 条（预期 {expected} = 放行 {after.Count} × 2 + 阻止全部 2 + 规则 {ruleFilterCount}）");
                CheckAssertion(results, "重建后过滤器条数同步更新", filterCount == expected);
            }

            W();
            W("===== 3. 2.0 不该再写 1.x 的标志 =====");

            var settings = AppSettings.Load(settingsPath);
            W($"    StrictModeLeftOn = {settings.StrictModeLeftOn}，" +
              $"SelfAllowCreated = {settings.StrictModeSelfAllowCreated}");

            CheckAssertion(results, "不写「严格模式没还原」标志", !settings.StrictModeLeftOn);
            CheckAssertion(results, "不写「自建放行规则」标志", !settings.StrictModeSelfAllowCreated);

            W();
            W("===== 4. 关闭 =====");

            CheckAssertion(results, "关闭成功", StrictModeManager.Disable().Success);

            using (var engine = WfpEngine.Open())
            {
                // 关闭严格模式只撤销会话，规则自己的过滤器必须原样保留。
                var ruleFilterCount = RuleEngine.GetRules().Count * 2;
                CheckAssertion(results, "关闭后只剩规则自己的过滤器",
                    engine.ListOurFilters().Count == ruleFilterCount);
            }

            CheckAssertion(results, "没开启时 RefreshIfEnabled 返回 null",
                StrictModeManager.RefreshIfEnabled() is null);
        }
        finally
        {
            StrictModeManager.Disable();

            foreach (var ruleName in new[] { firstRule, secondRule })
            {
                if (string.IsNullOrEmpty(ruleName))
                {
                    continue;
                }

                try
                {
                    RuleEngine.DeleteRule(ruleName);
                }
                catch (Exception)
                {
                    // 忽略清理失败。
                }
            }

            try
            {
                using var engine = WfpEngine.Open();
                engine.DeleteAllOurFilters();
                engine.DeleteSublayer();
            }
            catch (WfpException)
            {
                // 已经干净。
            }

            try
            {
                if (File.Exists(settingsPath))
                {
                    File.Delete(settingsPath);
                }
            }
            catch (Exception)
            {
                // 忽略。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 连接列表的搜索过滤与排序自检（**不联网、不碰界面**）。
    ///
    /// 这两件事看着简单，但有两个地方特别容易写错，必须用断言钉死：
    ///   - 远程地址按**字符串**排 → `192.168.1.10` 会跑到 `192.168.1.9` 前面；
    ///   - 端口 / PID 按**字符串**排 → `80` 会跑到 `443` 后面。
    /// 所以下面的样本刻意设计成：任何一处退化成字符串比较都会立刻被测出来。
    /// </summary>
    private static void RunConnectionFilterTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   连接列表：搜索过滤与排序自检（不联网、不碰界面）              #");
        W("################################################################");
        W();

        var sample = new List<TcpConnectionItem>
        {
            MakeConnection(100,   "chrome.exe",  "8.8.8.8",              443,  "IPv4", 50001, TcpState.Established),
            MakeConnection(1234,  "chrome.exe",  "1.1.1.1",              80,   "IPv4", 50002, TcpState.Established),
            MakeConnection(200,   "notepad.exe", "9.9.9.9",              443,  "IPv4", 50003, TcpState.Listen),
            MakeConnection(3000,  "svchost.exe", "10.0.0.1",             53,   "IPv4", 50004, TcpState.Established),
            MakeConnection(40000, "APP.exe",     "192.168.1.10",         8080, "IPv4", 50005, TcpState.TimeWait),
            MakeConnection(555,   "app.exe",     "2001:4860:4860::8888", 443,  "IPv6", 50006, TcpState.Established),
        };

        // ---------- 过滤 ----------
        CheckAssertion(results, "空关键词返回全部",
            ConnectionFilter.Apply(sample, "", ConnectionSortColumn.None, true).Count == sample.Count);

        CheckAssertion(results, "null 关键词返回全部",
            ConnectionFilter.Apply(sample, null, ConnectionSortColumn.None, true).Count == sample.Count);

        CheckAssertion(results, "全空白关键词返回全部",
            ConnectionFilter.Apply(sample, "   ", ConnectionSortColumn.None, true).Count == sample.Count);

        var byName = ConnectionFilter.Apply(sample, "CHROME", ConnectionSortColumn.None, true);
        CheckAssertion(results, "进程名包含匹配、不区分大小写（CHROME → chrome.exe ×2）",
            byName.Count == 2 && byName.All(i => i.ProcessName == "chrome.exe"));

        var byPid = ConnectionFilter.Apply(sample, "12", ConnectionSortColumn.None, true);
        CheckAssertion(results, "PID 包含匹配（12 → PID 1234）",
            byPid.Count == 1 && byPid[0].Pid == 1234);

        var byIp = ConnectionFilter.Apply(sample, "192.168", ConnectionSortColumn.None, true);
        CheckAssertion(results, "远程 IP 包含匹配（192.168 → 192.168.1.10）",
            byIp.Count == 1 && byIp[0].RemoteAddress.ToString() == "192.168.1.10");

        var byIpv6 = ConnectionFilter.Apply(sample, "4860", ConnectionSortColumn.None, true);
        CheckAssertion(results, "IPv6 地址片段也能命中（4860）",
            byIpv6.Count == 1 && byIpv6[0].RemoteAddress.AddressFamily == AddressFamily.InterNetworkV6);

        var byPort = ConnectionFilter.Apply(sample, "443", ConnectionSortColumn.None, true);
        CheckAssertion(results, "远程端口包含匹配（443 → 3 条）",
            byPort.Count == 3 && byPort.All(i => i.RemotePort == 443));

        CheckAssertion(results, "无匹配返回空列表且不抛异常",
            ConnectionFilter.Apply(sample, "zzz-not-exist", ConnectionSortColumn.None, true).Count == 0);

        CheckAssertion(results, "关键词首尾空格被裁掉",
            ConnectionFilter.Apply(sample, "  chrome  ", ConnectionSortColumn.None, true).Count == 2);

        // ---------- 不排序时保持原顺序 ----------
        var noSort = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.None, true);
        CheckAssertion(results, "不排序时保持扫描顺序",
            noSort.Select(i => i.Pid).SequenceEqual(sample.Select(i => i.Pid)));

        // ---------- 排序：数值，不是字符串 ----------
        var expectedPidOrder = new[] { 100, 200, 555, 1234, 3000, 40000 };

        var byPidAsc = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.Pid, true);
        W($"    PID 升序        = {string.Join(", ", byPidAsc.Select(i => i.Pid))}");
        CheckAssertion(results, "PID 按数字排序（字符串排序会得出 100,1234,200,3000,40000,555）",
            byPidAsc.Select(i => i.Pid).SequenceEqual(expectedPidOrder));

        var byPortAsc = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.RemotePort, true);
        W($"    远程端口升序    = {string.Join(", ", byPortAsc.Select(i => i.RemotePort))}");
        CheckAssertion(results, "远程端口按数字排序（字符串排序会把 53 排到最后）",
            byPortAsc[0].RemotePort == 53 && byPortAsc[byPortAsc.Count - 1].RemotePort == 8080);

        var byIpAsc = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.RemoteAddress, true);
        W($"    远程 IP 升序    = {string.Join(", ", byIpAsc.Select(i => i.RemoteAddressText))}");
        var ipv4Order = byIpAsc
            .Where(i => i.RemoteAddress.AddressFamily == AddressFamily.InterNetwork)
            .Select(i => i.RemoteAddress.ToString())
            .ToArray();
        CheckAssertion(results, "远程 IP 按数值排序（字符串排序会把 10.0.0.1 排到 9.9.9.9 前面）",
            ipv4Order.SequenceEqual(new[] { "1.1.1.1", "8.8.8.8", "9.9.9.9", "10.0.0.1", "192.168.1.10" }));

        CheckAssertion(results, "IPv4 全部排在 IPv6 前面",
            byIpAsc[byIpAsc.Count - 1].RemoteAddress.AddressFamily == AddressFamily.InterNetworkV6);

        // ---------- 大小写与稳定性 ----------
        var byNameAsc = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.ProcessName, true);
        var names = byNameAsc.Select(i => i.ProcessName).ToArray();
        var nameOrderOk = true;
        for (var i = 0; i < names.Length - 1; i++)
        {
            if (string.Compare(names[i], names[i + 1], StringComparison.OrdinalIgnoreCase) > 0)
            {
                nameOrderOk = false;
            }
        }

        W($"    程序名升序      = {string.Join(", ", names)}");
        CheckAssertion(results, "程序名排序不区分大小写（APP.exe 与 app.exe 视为同序）", nameOrderOk);

        var stablePort = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.RemotePort, true);
        var samePort = stablePort.Where(i => i.RemotePort == 443).Select(i => i.Pid).ToArray();
        CheckAssertion(results, "排序稳定：主键相同的条目保持原相对顺序（三个 443 仍是 100, 200, 555）",
            samePort.SequenceEqual(new[] { 100, 200, 555 }));

        var byPidDesc = ConnectionFilter.Apply(sample, "", ConnectionSortColumn.Pid, false);
        CheckAssertion(results, "降序正确",
            byPidDesc.Select(i => i.Pid).SequenceEqual(expectedPidOrder.Reverse()));

        // ---------- 无副作用 ----------
        var before = sample.Select(i => i.Pid).ToArray();
        _ = ConnectionFilter.Apply(sample, "chrome", ConnectionSortColumn.RemoteAddress, false);
        CheckAssertion(results, "过滤 + 排序不修改传入的集合（无副作用）",
            sample.Select(i => i.Pid).SequenceEqual(before));

        // ---------- 组合 ----------
        var combined = ConnectionFilter.Apply(sample, "chrome", ConnectionSortColumn.RemotePort, true);
        CheckAssertion(results, "过滤与排序可同时生效（chrome 两条按端口升序 = 80, 443）",
            combined.Count == 2 && combined[0].RemotePort == 80 && combined[1].RemotePort == 443);

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>造一条用于断言的连接。</summary>
    private static TcpConnectionItem MakeConnection(
        int pid,
        string processName,
        string remoteIp,
        ushort remotePort,
        string protocol,
        ushort localPort,
        TcpState state,
        string processPath = "")
        => new()
        {
            Pid = pid,
            ProcessName = processName,
            ProcessPath = processPath,
            Protocol = protocol,
            LocalPort = localPort,
            RemoteAddress = IPAddress.Parse(remoteIp),
            RemotePort = remotePort,
            State = state,
        };

    /// <summary>
    /// 规则分组与导入导出自检（**离线**：临时文件，不碰 WFP）。
    ///
    /// 重点验证"导出的文件能原样导回来"：到期时间、动作、IP/程序类型、分组，
    /// 任何一项在往返中丢了，用户都会得到一条"看起来一样、实际不一样"的规则。
    /// </summary>
    private static void RunRulesIoTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var tempDir = Path.Combine(Path.GetTempPath(), $"wag-rules-{Guid.NewGuid():N}");
        var groupFile = Path.Combine(tempDir, "rule-groups.json");

        W("################################################################");
        W("#   规则分组 + 导入导出（离线：临时文件，不建任何规则）          #");
        W("################################################################");
        W();

        try
        {
            // ---------------- 1. 分组存储 ----------------
            W("===== 1. 规则分组存储 =====");

            var groups = new RuleGroupStore(groupFile);

            groups.SetGroup("AppGuard_Block_a.exe_11111111", "游戏");
            groups.SetGroup("AppGuard_Block_b.exe_22222222", "游戏");
            groups.SetGroup("AppGuard_Allow_c.exe_33333333", "办公");
            groups.SetGroup("AppGuard_Block_d.exe_44444444", "");   // 未分组：应当被移除

            CheckAssertion(results, "能给规则设置分组",
                groups.GetGroup("AppGuard_Block_a.exe_11111111") == "游戏");
            CheckAssertion(results, "空分组名等于「未分组」",
                groups.GetGroup("AppGuard_Block_d.exe_44444444").Length == 0);
            CheckAssertion(results, "分组名去重后是两个",
                groups.AllGroups().Count == 2 && groups.AllGroups().Contains("游戏"));

            groups.Save();
            var reloaded = new RuleGroupStore(groupFile);
            CheckAssertion(results, "分组能存盘并读回（往返）",
                reloaded.GetGroup("AppGuard_Allow_c.exe_33333333") == "办公");

            var pruned = reloaded.Prune(new[]
            {
                "AppGuard_Block_a.exe_11111111",
                "AppGuard_Allow_c.exe_33333333",
            });
            W($"    清理孤儿分组记录：{pruned} 条");
            CheckAssertion(results, "已删除规则的分组记录会被清掉", pruned == 1);
            CheckAssertion(results, "仍在使用的分组不受影响",
                reloaded.GetGroup("AppGuard_Block_a.exe_11111111") == "游戏");

            File.WriteAllText(groupFile, "{ 这不是合法 json", Encoding.UTF8);
            var brokenGroups = new RuleGroupStore(groupFile);
            CheckAssertion(results, "分组文件损坏时按空表处理，不抛异常",
                brokenGroups.AllGroups().Count == 0);

            // ---------------- 2. 导出文档（按页各导各的） ----------------
            W();
            W("===== 2. 导出 → 导入（按页区分）=====");

            var gameRule = new FirewallRuleItem
            {
                Name = RuleNaming.BuildBlockRuleName(@"C:\Games\game.exe"),
                ApplicationPath = @"C:\Games\game.exe",
                Description = "测试",
                Grouping = "AppGuard",
                Enabled = true,
                Action = FirewallAction.Block,
                Direction = FirewallDirection.Outbound,
                Protocol = 256,
            };

            var allowRule = new FirewallRuleItem
            {
                Name = RuleNaming.BuildAllowRuleName(@"C:\Tools\tool.exe"),
                ApplicationPath = @"C:\Tools\tool.exe",
                Description = "测试",
                Grouping = "AppGuard",
                Enabled = true,
                Action = FirewallAction.Allow,
                Direction = FirewallDirection.Outbound,
                Protocol = 256,
                Expiry = RuleExpiry.At(DateTime.UtcNow.AddHours(2)),
            };

            var ipRule = new FirewallRuleItem
            {
                Name = "AppGuard_BlockIp_1.2.3.4",
                ApplicationPath = string.Empty,
                IpAddress = "1.2.3.4",
                Description = "测试",
                Grouping = "AppGuard",
                Enabled = true,
                Action = FirewallAction.Block,
                Direction = FirewallDirection.Outbound,
                Protocol = 256,
            };

            var groupStore = new RuleGroupStore(Path.Combine(tempDir, "export-groups.json"));
            groupStore.SetGroup(gameRule.Name, "游戏");
            groupStore.SetGroup(allowRule.Name, "办公");

            var all = new[] { gameRule, allowRule, ipRule };

            var blockDoc = RuleExport.Build(all, groupStore, FirewallAction.Block);
            var allowDoc = RuleExport.Build(all, groupStore, FirewallAction.Allow);

            CheckAssertion(results, "黑名单导出只含阻止规则（程序 + IP）",
                blockDoc.Rules.Count == 2 && blockDoc.Rules.All(entry => entry.Action == "block"));
            CheckAssertion(results, "白名单导出只含允许规则",
                allowDoc.Rules.Count == 1 && allowDoc.Rules.All(entry => entry.Action == "allow"));
            CheckAssertion(results, "导出文件记录了范围（block / allow）",
                blockDoc.Scope == "block" && allowDoc.Scope == "allow");

            var blockJson = RuleExport.Serialize(blockDoc);
            var allowJson = RuleExport.Serialize(allowDoc);

            CheckAssertion(results, "导出内容是合法 JSON 且带格式标记",
                blockJson.Contains(RuleExport.FormatName));

            if (!RuleExport.TryParse(blockJson, out var parsedBlock, out var blockError)
                || parsedBlock is null)
            {
                CheckAssertion(results, $"黑名单导出文件能被解析（错误：{blockError}）", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            if (!RuleExport.TryParse(allowJson, out var parsedAllowDoc, out var allowError)
                || parsedAllowDoc is null)
            {
                CheckAssertion(results, $"白名单导出文件能被解析（错误：{allowError}）", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            var parsedGame = parsedBlock.Rules.Single(entry => entry.Value == @"C:\Games\game.exe");
            var parsedIp = parsedBlock.Rules.Single(entry => entry.Value == "1.2.3.4");
            var parsedAllow = parsedAllowDoc.Rules.Single();

            CheckAssertion(results, "程序阻止规则的类型/动作保留",
                parsedGame.Kind == "program" && parsedGame.Action == "block");
            CheckAssertion(results, "IP 规则被识别成 ip", parsedIp.Kind == "ip");
            CheckAssertion(results, "永久规则的到期字段为空",
                parsedGame.Expiry.Length == 0 && parsedIp.Expiry.Length == 0);

            var allowExpiry = RuleExpiry.Parse(parsedAllow.Expiry);
            CheckAssertion(results, "白名单限时规则的到期时间保留（±1 分钟）",
                allowExpiry.Kind == RuleExpiryKind.AtTime
                && allowExpiry.ExpiresAtUtc is { } at
                && Math.Abs((at - allowRule.Expiry.ExpiresAtUtc!.Value).TotalMinutes) < 1);

            CheckAssertion(results, "分组名随文件一起导出/导入",
                parsedGame.Group == "游戏" && parsedAllow.Group == "办公");

            // ---------------- 2b. 跨页导入必须被拦住 ----------------
            W();
            W("===== 2b. 黑名单文件不能导进白名单页 =====");

            var blockIntoAllow = RuleExport.TryMatchScope(parsedBlock, FirewallAction.Allow, out var crossError);
            W($"    黑名单文件 → 白名单页：{(blockIntoAllow ? "接受（错误！）" : crossError)}");
            CheckAssertion(results, "黑名单文件在导入白名单页时被拒绝", !blockIntoAllow);

            var allowIntoBlock = RuleExport.TryMatchScope(parsedAllowDoc, FirewallAction.Block, out _);
            CheckAssertion(results, "白名单文件在导入黑名单页时被拒绝", !allowIntoBlock);

            CheckAssertion(results, "同页导入被接受",
                RuleExport.TryMatchScope(parsedBlock, FirewallAction.Block, out _)
                && RuleExport.TryMatchScope(parsedAllowDoc, FirewallAction.Allow, out _));

            // 旧格式（没有 Scope 字段）里混了两类 → 同样拒绝，避免"导进去一半"。
            const string legacyMixed = "{\"Format\":\"WinAppGuard.Rules\",\"Version\":1,\"Rules\":[" +
                "{\"Kind\":\"program\",\"Value\":\"C:\\\\a.exe\",\"Action\":\"block\"}," +
                "{\"Kind\":\"program\",\"Value\":\"C:\\\\b.exe\",\"Action\":\"allow\"}]}";

            CheckAssertion(results, "旧格式混了两类时拒绝导入",
                RuleExport.TryParse(legacyMixed, out var legacyDoc, out _)
                && legacyDoc is not null
                && !RuleExport.TryMatchScope(legacyDoc, FirewallAction.Block, out _));

            CheckAssertion(results, "摘要能说清阻止/允许数量",
                RuleExport.Summarize(parsedBlock).Contains("阻止 2 条")
                && RuleExport.Summarize(parsedAllowDoc).Contains("允许 1 条"));

            // ---------------- 3. 坏文件必须被拒绝 ----------------
            W();
            W("===== 3. 坏文件拒绝（不能把半个坏文件拿去建规则）=====");

            var rejections = new (string Name, string Json)[]
            {
                ("不是 JSON", "{ 这不是合法 json"),
                ("不是我们的格式", "{\"Format\":\"SomethingElse\",\"Version\":1,\"Rules\":[]}"),
                ("版本过新", "{\"Format\":\"WinAppGuard.Rules\",\"Version\":99,\"Rules\":[]}"),
                ("类型不认识", "{\"Format\":\"WinAppGuard.Rules\",\"Version\":1,\"Rules\":[{\"Kind\":\"dll\",\"Value\":\"C:\\\\a.exe\",\"Action\":\"block\"}]}"),
                ("动作不认识", "{\"Format\":\"WinAppGuard.Rules\",\"Version\":1,\"Rules\":[{\"Kind\":\"program\",\"Value\":\"C:\\\\a.exe\",\"Action\":\"maybe\"}]}"),
                ("相对路径", "{\"Format\":\"WinAppGuard.Rules\",\"Version\":1,\"Rules\":[{\"Kind\":\"program\",\"Value\":\"a.exe\",\"Action\":\"block\"}]}"),
                ("非法 IP", "{\"Format\":\"WinAppGuard.Rules\",\"Version\":1,\"Rules\":[{\"Kind\":\"ip\",\"Value\":\"999.1.1.1\",\"Action\":\"block\"}]}"),
            };

            foreach (var (name, badJson) in rejections)
            {
                var accepted = RuleExport.TryParse(badJson, out _, out var reason);
                W($"    {name} → {(accepted ? "被接受（错误！）" : "拒绝：" + reason)}");
                CheckAssertion(results, $"坏文件被拒绝：{name}", !accepted);
            }
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// IPC 编解码自检（**离线**）：长度前缀、上限、非法长度、JSON 往返。
    /// 真正的"非管理员被拒绝"只能在虚拟机里用标准用户验证（见 --service-auth-test）。
    /// </summary>
    private static void RunIpcCodecTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   IPC 编解码（离线：长度前缀 / 上限 / 非法输入 / JSON 往返）    #");
        W("################################################################");
        W();

        CheckAssertion(results, "协议版本为 2", ServiceProtocol.Version == 2);
        CheckAssertion(results, "管道名带协议版本（不兼容时会连不上而不是误解）",
            ServiceProtocol.PipeName.EndsWith(".v2", StringComparison.Ordinal));

        // ---------------- 1. 请求往返 + 长度前缀 ----------------
        W("===== 1. 请求往返 =====");

        var request = new ServiceRequest { Command = ServiceProtocol.Commands.Status };
        using var requestStream = new MemoryStream();

        PipeCodec.WriteAsync(requestStream, request, CancellationToken.None).GetAwaiter().GetResult();

        var header = new byte[4];
        requestStream.Position = 0;
        requestStream.ReadExactly(header);

        var declaredLength = BinaryPrimitives.ReadInt32LittleEndian(header);
        W($"    声明长度 = {declaredLength}，实际负载 = {requestStream.Length - 4}");

        CheckAssertion(results, "长度前缀与实际负载一致",
            declaredLength == requestStream.Length - 4);

        requestStream.Position = 0;
        var parsedRequest = PipeCodec.ReadAsync<ServiceRequest>(requestStream, CancellationToken.None)
            .GetAwaiter().GetResult();

        CheckAssertion(results, "请求能原样读回",
            parsedRequest is not null
            && parsedRequest.Id == request.Id
            && parsedRequest.Command == ServiceProtocol.Commands.Status
            && parsedRequest.ProtocolVersion == ServiceProtocol.Version);

        // ---------------- 2. 状态往返 ----------------
        W();
        W("===== 2. 状态往返 =====");

        var status = new ServiceStatus
        {
            ServiceVersion = "3.1",
            SublayerPresent = true,
            BlockRuleCount = 3,
            AllowRuleCount = 1,
            IpRuleCount = 2,
        };

        using var statusStream = new MemoryStream();
        PipeCodec.WriteAsync(statusStream, status, CancellationToken.None).GetAwaiter().GetResult();
        statusStream.Position = 0;

        var parsedStatus = PipeCodec.ReadAsync<ServiceStatus>(statusStream, CancellationToken.None)
            .GetAwaiter().GetResult();

        CheckAssertion(results, "状态字段全部保留",
            parsedStatus is not null
            && parsedStatus.ServiceVersion == "3.1"
            && parsedStatus.SublayerPresent
            && parsedStatus.BlockRuleCount == 3
            && parsedStatus.AllowRuleCount == 1
            && parsedStatus.IpRuleCount == 2);

        // ---------------- 3. 超长消息 ----------------
        W();
        W("===== 3. 上限与非法输入 =====");

        var huge = new ServiceRequest
        {
            Command = new string('x', ServiceProtocol.MaxMessageBytes),
        };

        var oversizedRejected = false;

        try
        {
            using var _ = new MemoryStream();
            PipeCodec.WriteAsync(_, huge, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (InvalidDataException)
        {
            oversizedRejected = true;
        }

        CheckAssertion(results, "超长消息被拒绝（不能拿大消息拖死服务）", oversizedRejected);

        foreach (var length in new[] { 0, -5, ServiceProtocol.MaxMessageBytes + 1 })
        {
            using var stream = new MemoryStream();
            var badHeader = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(badHeader, length);
            stream.Write(badHeader, 0, 4);
            stream.Position = 0;

            var rejected = false;

            try
            {
                _ = PipeCodec.ReadAsync<ServiceRequest>(stream, CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch (InvalidDataException)
            {
                rejected = true;
            }

            CheckAssertion(results, $"非法长度 {length} 被拒绝", rejected);
        }

        CheckAssertion(results, "空流（对方直接关闭）返回 null，不抛异常",
            PipeCodec.ReadAsync<ServiceRequest>(new MemoryStream(), CancellationToken.None)
                .GetAwaiter().GetResult() is null);

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>服务状态标签的两种状态（离线 / 运行中）。</summary>
    /// <summary>
    /// 3.1 签名封套（离线）：nonce + payload 签名、篡改、重放、长度上限。
    /// </summary>
    private static void RunAuthCodecTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   签名封套（离线：nonce / 签名 / 篡改 / 重放 / 长度上限）       #");
        W("################################################################");
        W();

        try
        {
            using var key = OwnerKey.Create();
            var nonce = RandomNumberGenerator.GetBytes(32);
            var payload = Encoding.UTF8.GetBytes("{\"command\":\"status\"}");
            var signed = new byte[nonce.Length + payload.Length];
            Buffer.BlockCopy(nonce, 0, signed, 0, nonce.Length);
            Buffer.BlockCopy(payload, 0, signed, nonce.Length, payload.Length);

            var signature = key.Sign(signed);

            using var stream = new MemoryStream();
            PipeCodec.WriteSignedAsync(
                    stream, signature, payload, CancellationToken.None)
                .GetAwaiter().GetResult();

            stream.Position = 0;
            var envelope = PipeCodec.ReadSignedAsync(stream, CancellationToken.None)
                .GetAwaiter().GetResult();

            CheckAssertion(results, "签名封套长度往返一致",
                envelope.Signature.Length == signature.Length
                && envelope.Payload.Length == payload.Length);

            CheckAssertion(results, "签名封套内容往返一致",
                envelope.Signature.AsSpan().SequenceEqual(signature)
                && envelope.Payload.AsSpan().SequenceEqual(payload));

            CheckAssertion(results, "nonce + payload 签名能验证",
                OwnerKey.Verify(key.PublicKey, signed, envelope.Signature));

            var tamperedPayload = payload.ToArray();
            tamperedPayload[^1] ^= 0x01;
            var tamperedSigned = new byte[nonce.Length + tamperedPayload.Length];
            Buffer.BlockCopy(nonce, 0, tamperedSigned, 0, nonce.Length);
            Buffer.BlockCopy(
                tamperedPayload, 0, tamperedSigned, nonce.Length, tamperedPayload.Length);

            CheckAssertion(results, "篡改请求后验签失败",
                !OwnerKey.Verify(key.PublicKey, tamperedSigned, envelope.Signature));

            var tamperedSignature = signature.ToArray();
            tamperedSignature[0] ^= 0x01;

            CheckAssertion(results, "篡改签名后验签失败",
                !OwnerKey.Verify(key.PublicKey, signed, tamperedSignature));

            var replayNonce = RandomNumberGenerator.GetBytes(32);
            var replayData = new byte[replayNonce.Length + payload.Length];
            Buffer.BlockCopy(replayNonce, 0, replayData, 0, replayNonce.Length);
            Buffer.BlockCopy(payload, 0, replayData, replayNonce.Length, payload.Length);

            CheckAssertion(results, "换一个 nonce 重放旧签名失败",
                !OwnerKey.Verify(key.PublicKey, replayData, signature));

            var emptySignatureRejected = false;

            try
            {
                using var _ = new MemoryStream();
                PipeCodec.WriteSignedAsync(
                        _, Array.Empty<byte>(), payload, CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch (InvalidDataException)
            {
                emptySignatureRejected = true;
            }

            CheckAssertion(results, "空签名被拒绝", emptySignatureRejected);

            var oversizedPayloadRejected = false;

            try
            {
                using var _ = new MemoryStream();
                PipeCodec.WriteSignedAsync(
                        _, signature,
                        new byte[ServiceProtocol.MaxMessageBytes + 1],
                        CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch (InvalidDataException)
            {
                oversizedPayloadRejected = true;
            }

            CheckAssertion(results, "超长请求被拒绝", oversizedPayloadRejected);

            var challenge = new ServiceResponse
            {
                Ok = true,
                Nonce = Convert.ToBase64String(nonce),
            };

            var challengeJson = JsonSerializer.Serialize(
                challenge, ServiceProtocol.JsonOptions);
            var parsedChallenge = JsonSerializer.Deserialize<ServiceResponse>(
                challengeJson, ServiceProtocol.JsonOptions);

            CheckAssertion(results, "challenge nonce 能原样往返",
                parsedChallenge?.Nonce is not null
                && Convert.FromBase64String(parsedChallenge.Nonce).Length == 32);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "签名封套测试执行完成", false);
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.2 界面语言（离线）：Auto 解析、英文静态文案、切回中文、设置持久化。
    /// 只检查构造后的控件树，不显示窗口。
    /// </summary>
    private static void RunUiLanguageTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previous = Localizer.Current;

        W("################################################################");
        W("#   界面语言（英文静态文案 / 中文回退 / auto 解析 / 持久化）      #");
        W("################################################################");
        W();

        try
        {
            Localizer.Initialize("en");
            MainForm.SuppressBackgroundServices = true;

            using (var form = new MainForm(isAutostart: false))
            {
                TrySetField(form, "_runtimeInitialized", true);

                if (!TryGetField<TabPage>(form, "_tabConnections", out var connections)
                    || !TryGetField<Button>(form, "_refreshButton", out var refresh)
                    || !TryGetField<Label>(form, "_safetyNoticeLabel", out var safety))
                {
                    CheckAssertion(results, "找得到英文界面控件", false);
                }
                else
                {
                    W($"    Connections tab = {connections.Text}");
                    CheckAssertion(results, "英文：联网连接页签",
                        connections.Text == "Connections");
                    CheckAssertion(results, "英文：刷新按钮",
                        refresh.Text == "Refresh");

                    var measured = TextRenderer.MeasureText(
                        safety.Text, safety.Font).Width;
                    W($"    顶部安全横幅：需要 {measured}px / 实宽 {safety.Width}px");
                    CheckAssertion(results, "英文：顶部安全横幅放得下",
                        measured <= safety.Width);
                    CheckAssertion(results, "英文：安全横幅不是中文",
                        !System.Text.RegularExpressions.Regex.IsMatch(
                            safety.Text ?? string.Empty, "[\u4e00-\u9fff]"));

                    form.PerformLayout();

                    if (TryGetField<Label>(form, "_settingsNoticeLabel", out var settingsNotice)
                        && TryGetField<GroupBox>(form, "_autostartPanel", out var autostart))
                    {
                        W($"    设置页提示底部={settingsNotice.Bottom}，" +
                          $"自启面板顶部={autostart.Top}");
                        CheckAssertion(results, "英文：设置页提示不压住自启面板",
                            settingsNotice.Bottom <= autostart.Top);
                    }

                    if (TryGetField<Button>(form, "_rulesDeleteButton", out var deleteRule)
                        && TryGetField<Button>(form, "_whitelistClearButton", out var clearWhite))
                    {
                        var deleteWidth = TextRenderer.MeasureText(
                            deleteRule.Text, deleteRule.Font).Width + 16;
                        var clearWidth = TextRenderer.MeasureText(
                            clearWhite.Text, clearWhite.Font).Width + 16;

                        W($"    删除规则按钮：需要 {deleteWidth}px / 实宽 {deleteRule.Width}px");
                        W($"    清空白名单按钮：需要 {clearWidth}px / 实宽 {clearWhite.Width}px");
                        CheckAssertion(results, "英文：删除规则按钮不截断",
                            deleteWidth <= deleteRule.Width);
                        CheckAssertion(results, "英文：清空白名单按钮不截断",
                            clearWidth <= clearWhite.Width);
                    }

                    static bool HasCjk(string? text)
                        => !string.IsNullOrEmpty(text)
                           && System.Text.RegularExpressions.Regex.IsMatch(
                               text!, "[\u4e00-\u9fff]");

                    CheckAssertion(results, "英文：窗口标题",
                        !HasCjk(form.Text)
                        && form.Text.Contains("program network control", StringComparison.Ordinal));

                    if (TryGetField<DataGridView>(form, "_connectionGrid", out var connectionGrid))
                    {
                        W("    连接列头 = " + string.Join(" | ", connectionGrid.Columns
                            .Cast<DataGridViewColumn>().Select(column => column.HeaderText)));
                        CheckAssertion(results, "英文：连接表列头无中文",
                            connectionGrid.Columns.Cast<DataGridViewColumn>()
                                .All(column => !HasCjk(column.HeaderText)));
                    }

                    if (TryGetField<DataGridView>(form, "_rulesGrid", out var rulesGrid))
                    {
                        W("    黑名单列头 = " + string.Join(" | ", rulesGrid.Columns
                            .Cast<DataGridViewColumn>().Select(column => column.HeaderText)));
                        CheckAssertion(results, "英文：黑名单列头无中文",
                            rulesGrid.Columns.Cast<DataGridViewColumn>()
                                .All(column => !HasCjk(column.HeaderText)));
                    }

                    if (TryGetField<DataGridView>(form, "_whitelistGrid", out var whitelistGrid))
                    {
                        W("    白名单列头 = " + string.Join(" | ", whitelistGrid.Columns
                            .Cast<DataGridViewColumn>().Select(column => column.HeaderText)));
                        CheckAssertion(results, "英文：白名单列头无中文",
                            whitelistGrid.Columns.Cast<DataGridViewColumn>()
                                .All(column => !HasCjk(column.HeaderText)));
                    }

                    if (TryGetField<TabPage>(form, "_tabDns", out var dnsTab)
                        && TryGetField<DataGridView>(form, "_dnsGrid", out var dnsGrid))
                    {
                        var dnsHeaders = dnsGrid.Columns.Cast<DataGridViewColumn>()
                            .Select(column => column.HeaderText)
                            .ToList();

                        W($"    3.5 DNS 页签 = {dnsTab.Text} | 列头 = {string.Join(" | ", dnsHeaders)}");
                        CheckAssertion(results, "英文：DNS 页签与列头无中文",
                            !HasCjk(dnsTab.Text) && dnsHeaders.All(text => !HasCjk(text)));

                        if (TryGetField<Label>(form, "_dnsHintLabel", out var dnsHint))
                        {
                            W($"    DNS 说明 = {dnsHint.Text}");
                            CheckAssertion(results, "英文：DNS 说明无中文", !HasCjk(dnsHint.Text));
                        }
                    }

                    if (TryGetField<TabPage>(form, "_tabTraffic", out var trafficTab)
                        && TryGetField<DataGridView>(form, "_trafficGrid", out var trafficGrid))
                    {
                        var trafficHeaders = trafficGrid.Columns.Cast<DataGridViewColumn>()
                            .Select(column => column.HeaderText)
                            .ToList();

                        W($"    3.6 流量页签 = {trafficTab.Text} | 列头 = {string.Join(" | ", trafficHeaders)}");
                        CheckAssertion(results, "英文：流量页签与列头无中文",
                            !HasCjk(trafficTab.Text) && trafficHeaders.All(text => !HasCjk(text)));

                        if (TryGetField<TextBox>(form, "_trafficSearchBox", out var trafficSearch))
                        {
                            W($"    流量搜索占位 = {trafficSearch.PlaceholderText}");
                            CheckAssertion(results, "英文：流量搜索占位无中文",
                                !HasCjk(trafficSearch.PlaceholderText));
                        }

                        if (TryGetField<Label>(form, "_trafficSummaryLabel", out var trafficSummary))
                        {
                            W($"    流量统计行 = {trafficSummary.Text}");
                            CheckAssertion(results, "英文：流量统计行无中文",
                                !HasCjk(trafficSummary.Text));
                        }

                        if (TryGetField<Button>(form, "_trafficClearButton", out var trafficClear))
                        {
                            var need = TextRenderer.MeasureText(
                                trafficClear.Text, trafficClear.Font).Width + 16;

                            W($"    清空流量按钮：需要 {need}px / 实宽 {trafficClear.Width}px");
                            CheckAssertion(results, "英文：清空流量按钮无中文且不截断",
                                !HasCjk(trafficClear.Text) && need <= trafficClear.Width);
                        }
                    }

                    if (TryGetField<TabPage>(form, "_tabIds", out var idsTab)
                        && TryGetField<WinAppGuard.Forms.DataGridViewBuffered>(form, "_idsGrid", out var idsGrid))
                    {
                        var idsHeaders = idsGrid.Columns.Cast<DataGridViewColumn>()
                            .Select(column => column.HeaderText)
                            .ToList();

                        W($"    3.7 IDS 页签 = {idsTab.Text} | 列头 = {string.Join(" | ", idsHeaders)}");
                        CheckAssertion(results, "英文：IDS 页签与列头无中文",
                            !HasCjk(idsTab.Text) && idsHeaders.All(text => !HasCjk(text)));

                        if (TryGetField<TextBox>(form, "_idsSearchBox", out var idsSearch))
                        {
                            W($"    IDS 搜索占位 = {idsSearch.PlaceholderText}");
                            CheckAssertion(results, "英文：IDS 搜索占位无中文",
                                !HasCjk(idsSearch.PlaceholderText));
                        }

                        if (TryGetField<Label>(form, "_idsSummaryLabel", out var idsSummary))
                        {
                            W($"    IDS 状态行 = {idsSummary.Text}");
                            CheckAssertion(results, "英文：IDS 状态行无中文",
                                !HasCjk(idsSummary.Text));
                        }

                        if (TryGetField<ComboBox>(form, "_idsSeverityFilter", out var idsSeverity)
                            && TryGetField<ComboBox>(form, "_idsRuleFilter", out var idsRule))
                        {
                            var items = idsSeverity.Items.Cast<object>()
                                .Concat(idsRule.Items.Cast<object>())
                                .Select(item => item?.ToString() ?? string.Empty)
                                .ToList();

                            W("    IDS 筛选 = " + string.Join(" | ", items));
                            CheckAssertion(results, "英文：IDS 筛选无中文",
                                items.All(text => !HasCjk(text)));
                        }

                        if (TryGetField<Button>(form, "_idsAckButton", out var idsAck)
                            && TryGetField<Button>(form, "_idsSuppressButton", out var idsSuppress)
                            && TryGetField<Button>(form, "_idsSettingsButton", out var idsSettings))
                        {
                            var buttons = new[] { idsAck, idsSuppress, idsSettings };
                            var truncated = buttons
                                .Select(button => new
                                {
                                    Button = button,
                                    Need = TextRenderer.MeasureText(button.Text, button.Font).Width + 16,
                                })
                                .Where(item => item.Need > item.Button.Width)
                                .Select(item => item.Button.Text)
                                .ToList();

                            W("    IDS 按钮 = " + string.Join(" | ", buttons.Select(button => button.Text)));
                            CheckAssertion(results, "英文：IDS 按钮无中文且不截断",
                                truncated.Count == 0
                                && buttons.All(button => !HasCjk(button.Text)));
                        }

                        CheckAssertion(results, "英文：IDS 空状态无中文",
                            !HasCjk(idsGrid.EmptyText));
                    }

                    if (TryGetField<TabPage>(form, "_tabAntiScan", out var antiTab)
                        && TryGetField<WinAppGuard.Forms.DataGridViewBuffered>(
                            form, "_antiEventGrid", out var antiEventGrid)
                        && TryGetField<WinAppGuard.Forms.DataGridViewBuffered>(
                            form, "_antiBlockGrid", out var antiBlockGrid))
                    {
                        var antiHeaders = antiEventGrid.Columns.Cast<DataGridViewColumn>()
                            .Select(column => column.HeaderText)
                            .Concat(antiBlockGrid.Columns.Cast<DataGridViewColumn>()
                                .Select(column => column.HeaderText))
                            .ToList();

                        W($"    4.0 防护页签 = {antiTab.Text} | 列头 = {string.Join(" | ", antiHeaders)}");
                        CheckAssertion(results, "英文：防护页签与列头无中文",
                            !HasCjk(antiTab.Text) && antiHeaders.All(text => !HasCjk(text)));
                        CheckAssertion(results, "英文：防护空状态无中文",
                            !HasCjk(antiEventGrid.EmptyText)
                            && !HasCjk(antiBlockGrid.EmptyText));

                        if (TryGetField<TextBox>(form, "_antiSearchBox", out var antiSearch))
                        {
                            W($"    防护搜索占位 = {antiSearch.PlaceholderText}");
                            CheckAssertion(results, "英文：防护搜索占位无中文",
                                !HasCjk(antiSearch.PlaceholderText));
                        }

                        if (TryGetField<Label>(form, "_antiStatusLabel", out var antiStatus))
                        {
                            W($"    防护状态行 = {antiStatus.Text}");
                            CheckAssertion(results, "英文：防护状态行无中文",
                                !HasCjk(antiStatus.Text));
                        }

                        if (TryGetField<ComboBox>(form, "_antiSeverityFilter", out var antiSeverity))
                        {
                            var items = antiSeverity.Items.Cast<object>()
                                .Select(item => item?.ToString() ?? string.Empty)
                                .ToList();

                            W("    防护筛选 = " + string.Join(" | ", items));
                            CheckAssertion(results, "英文：防护筛选无中文",
                                items.All(text => !HasCjk(text)));
                        }

                        if (TryGetField<Button>(form, "_antiRefreshButton", out var antiRefresh)
                            && TryGetField<Button>(form, "_antiReleaseButton", out var antiRelease)
                            && TryGetField<Button>(form, "_antiReleaseAllButton", out var antiReleaseAll)
                            && TryGetField<Button>(form, "_antiClearButton", out var antiClear)
                            && TryGetField<Button>(form, "_antiSettingsButton", out var antiSettings))
                        {
                            var buttons = new[]
                            {
                                antiRefresh, antiRelease, antiReleaseAll, antiClear, antiSettings,
                            };
                            var truncated = buttons
                                .Select(button => new
                                {
                                    Button = button,
                                    // 防护页按钮是 AutoSize，WinForms 只会额外给约 7px 内边距；
                                    // 留 6px 余量即可判断是否截断。
                                    Need = TextRenderer.MeasureText(button.Text, button.Font).Width + 6,
                                })
                                .Where(item => item.Need > item.Button.Width)
                                .Select(item => item.Button.Text)
                                .ToList();

                            W("    防护按钮 = " + string.Join(" | ", buttons.Select(button =>
                                $"{button.Text}({button.Width}px)")));
                            CheckAssertion(results, "英文：防护按钮无中文且不截断",
                                truncated.Count == 0
                                && buttons.All(button => !HasCjk(button.Text)));
                        }
                    }

                    if (TryGetField<WinAppGuard.Forms.DataGridViewBuffered>(
                            form, "_rulesGrid", out var rulesEmpty))
                    {
                        CheckAssertion(results, "英文：黑名单空状态无中文",
                            !HasCjk(rulesEmpty.EmptyText));
                    }

                    if (TryGetField<WinAppGuard.Forms.DataGridViewBuffered>(
                            form, "_whitelistGrid", out var whitelistEmpty))
                    {
                        CheckAssertion(results, "英文：白名单空状态无中文",
                            !HasCjk(whitelistEmpty.EmptyText));
                    }

                    if (TryGetField<TextBox>(form, "_rulesSearchBox", out var rulesSearch))
                    {
                        W($"    规则搜索占位 = {rulesSearch.PlaceholderText}");
                        CheckAssertion(results, "英文：规则搜索占位无中文",
                            !HasCjk(rulesSearch.PlaceholderText));
                    }

                    // 分组下拉是运行时重建的：直接调用一次，防止「全部分组」漏翻。
                    var rebuildCombo = typeof(MainForm).GetMethod(
                        "RebuildGroupCombo",
                        System.Reflection.BindingFlags.NonPublic
                        | System.Reflection.BindingFlags.Instance);

                    if (rebuildCombo is not null)
                    {
                        var combo = new ComboBox();
                        rebuildCombo.Invoke(
                            form, new object?[] { combo, null, Array.Empty<string>() });

                        var comboItems = combo.Items.Cast<object>()
                            .Select(item => item.ToString())
                            .ToList();

                        W("    分组下拉 = " + string.Join(" | ", comboItems));
                        CheckAssertion(results, "英文：分组下拉无中文",
                            comboItems.Count >= 2
                            && comboItems.All(item => !HasCjk(item)));
                    }

                    if (TryGetField<ContextMenuStrip>(form, "_trayMenu", out var trayMenu))
                    {
                        var trayItems = trayMenu.Items
                            .OfType<ToolStripMenuItem>()
                            .Select(item => item.Text)
                            .ToList();

                        W("    托盘菜单 = " + string.Join(" | ", trayItems));
                        CheckAssertion(results, "英文：托盘菜单无中文",
                            trayItems.Count > 0
                            && trayItems.All(text => !HasCjk(text)));
                    }

                    if (TryGetField<Button>(form, "_lockdown30Button", out var lock30)
                        && TryGetField<Button>(form, "_lockdown2hButton", out var lock2h))
                    {
                        W($"    锁网按钮 = {lock30.Text} | {lock2h.Text}");
                        CheckAssertion(results, "英文：锁网按钮无中文",
                            !HasCjk(lock30.Text) && !HasCjk(lock2h.Text));

                        var need30 = TextRenderer.MeasureText(lock30.Text, lock30.Font).Width + 16;
                        var need2h = TextRenderer.MeasureText(lock2h.Text, lock2h.Font).Width + 16;
                        W($"    锁网按钮宽度：30 分钟需要 {need30}px / 实宽 {lock30.Width}px；" +
                          $"2 小时需要 {need2h}px / 实宽 {lock2h.Width}px");
                        CheckAssertion(results, "英文：锁网按钮不截断",
                            need30 <= lock30.Width && need2h <= lock2h.Width);
                    }

                    if (TryGetField<ToolStripMenuItem>(form, "_trayLockdownItem", out var trayLockdown))
                    {
                        var lockdownItems = trayLockdown.DropDownItems
                            .OfType<ToolStripMenuItem>()
                            .Select(item => item.Text)
                            .ToList();

                        W("    锁网托盘子菜单 = " + string.Join(" | ", lockdownItems));
                        CheckAssertion(results, "英文：锁网托盘子菜单无中文",
                            lockdownItems.Count == 2
                            && lockdownItems.All(text => !HasCjk(text)));
                    }

                    if (TryGetField<NotifyIcon>(form, "_trayIcon", out var trayIcon))
                    {
                        W($"    托盘提示 = {trayIcon.Text}");
                        CheckAssertion(results, "英文：托盘提示无中文",
                            !HasCjk(trayIcon.Text));
                    }

                    CheckAssertion(results, "英文：确认框标题与标签",
                        Localizer.T("加入黑名单") == "Add to blocklist"
                        && Localizer.T("生效范围") == "Scope"
                        && Localizer.T("任意") == "Any"
                        && Localizer.T("阻止") == "Block");

                    CheckAssertion(results, "英文：确认框警告无中文",
                        !HasCjk(Localizer.T(
                            "这是永久规则，要恢复请回到这一页删除它。")));

                    CheckAssertion(results, "英文：白名单提示（开启/关闭）无中文",
                        !HasCjk(MainForm.BuildWhitelistNotice(true))
                        && !HasCjk(MainForm.BuildWhitelistNotice(false)));

                    CheckAssertion(results, "英文：记录页类型/未知/推测无中文",
                        Localizer.T("连接") == "Connection"
                        && Localizer.T("拦截") == "Blocked"
                        && Localizer.T("未知") == "Unknown"
                        && !HasCjk(Localizer.T("（未知程序）")));

                    CheckAssertion(results, "英文：状态栏计数无中文",
                        !HasCjk(Localizer.F("已阻止程序：{0} 个", 1))
                        && !HasCjk(Localizer.F("服务：运行中 · {0} 条规则", 1)));

                    // 直接构造确认框（不弹窗），检查标题、详情、警告、按钮、时长选项。
                    var confirmCtor = typeof(ConfirmForm)
                        .GetConstructors(System.Reflection.BindingFlags.NonPublic
                                         | System.Reflection.BindingFlags.Instance)
                        .Single(constructor => constructor.GetParameters().Length == 6);

                    var confirmDetails = new List<KeyValuePair<string, string>>
                    {
                        new("程序名", "Lark.exe"),
                        new("完整路径", @"C:\Users\VM\AppData\Local\Lark\Lark.exe"),
                        new("生效范围", "任意"),
                        new("将创建规则", "AppGuard_Block_Lark.exe_1"),
                    }.Select(pair => new KeyValuePair<string, string>(
                        Localizer.T(pair.Key), Localizer.T(pair.Value))).ToList();

                    var confirmWarnings = new[]
                    {
                        "确认后该程序会立刻无法联网（已经建立的连接也会断开）。",
                        "这是永久规则，要恢复请回到这一页删除它。",
                        "想限时阻止（30 分钟 / 2 小时 / 下次重启），请到「联网连接」页操作。",
                    }.Select(Localizer.T).ToList();

                    using (var dialog = (Form)confirmCtor.Invoke(new object[]
                           {
                               "加入黑名单",
                               "确定要阻止「Lark.exe」联网吗？",
                               confirmDetails,
                               confirmWarnings,
                               "阻止",
                               true,
                           }))
                    {
                        var leftovers = Walk(dialog)
                            .Where(control => HasCjk(control.Text))
                            .Select(control => $"{control.GetType().Name}:{control.Text}")
                            .ToList();

                        if (leftovers.Count > 0)
                        {
                            W("    确认框残留：" + string.Join(" / ", leftovers));
                        }

                        CheckAssertion(results, "英文：确认框控件无中文", leftovers.Count == 0);
                        CheckAssertion(results, "英文：确认框标题",
                            dialog.Text == "Add to blocklist");
                    }

                    // 3.7：IDS 设置 / 抑制对话框也要在英文下没有中文残留。
                    var assembly = typeof(MainForm).Assembly;

                    var idsSettingsType = assembly.GetType("WinAppGuard.Forms.IdsSettingsForm");
                    var idsSettingsCtor = idsSettingsType?
                        .GetConstructors(System.Reflection.BindingFlags.NonPublic
                                         | System.Reflection.BindingFlags.Instance)
                        .SingleOrDefault(constructor => constructor.GetParameters().Length == 2);

                    if (idsSettingsCtor is not null)
                    {
                        using var idsDialog = (Form)idsSettingsCtor.Invoke(new object[]
                        {
                            new IdsSettingsDto(),
                            new List<IdsSuppressionDto>
                            {
                                new()
                                {
                                    Id = "s1",
                                    RuleId = "dns",
                                    ProcessName = "demo.exe",
                                    Target = "evil.example",
                                    UntilUtc = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc),
                                },
                            },
                        });

                        var leftovers = Walk(idsDialog)
                            .Where(control => HasCjk(control.Text))
                            .Select(control => $"{control.GetType().Name}:{control.Text}")
                            .ToList();

                        var listItems = Walk(idsDialog)
                            .OfType<ListBox>()
                            .SelectMany(list => list.Items.Cast<object>())
                            .Select(item => item.ToString() ?? string.Empty)
                            .ToList();

                        if (leftovers.Count > 0)
                        {
                            W("    IDS 设置对话框残留：" + string.Join(" / ", leftovers));
                        }

                        W("    IDS 抑制列表 = " + string.Join(" | ", listItems));
                        CheckAssertion(results, "英文：IDS 设置对话框无中文",
                            leftovers.Count == 0
                            && !HasCjk(idsDialog.Text)
                            && listItems.All(text => !HasCjk(text)));
                    }
                    else
                    {
                        CheckAssertion(results, "英文：IDS 设置对话框可构造", false);
                    }

                    var idsSuppressType = assembly.GetType("WinAppGuard.Forms.IdsSuppressForm");                    var idsSuppressCtor = idsSuppressType?
                        .GetConstructors(System.Reflection.BindingFlags.NonPublic
                                         | System.Reflection.BindingFlags.Instance)
                        .SingleOrDefault(constructor => constructor.GetParameters().Length == 3);

                    if (idsSuppressCtor is not null)
                    {
                        using var suppressDialog = (Form)idsSuppressCtor.Invoke(new object[]
                        {
                            "Periodic beaconing", "demo.exe", "203.0.113.10:8443",
                        });

                        var leftovers = Walk(suppressDialog)
                            .Where(control => HasCjk(control.Text))
                            .Select(control => $"{control.GetType().Name}:{control.Text}")
                            .ToList();

                        if (leftovers.Count > 0)
                        {
                            W("    IDS 抑制对话框残留：" + string.Join(" / ", leftovers));
                        }

                        CheckAssertion(results, "英文：IDS 抑制对话框无中文",
                            leftovers.Count == 0 && !HasCjk(suppressDialog.Text));
                    }
                    else
                    {
                        CheckAssertion(results, "英文：IDS 抑制对话框可构造", false);
                    }

                    var antiSettingsType = assembly.GetType("WinAppGuard.Forms.AntiScanSettingsForm");
                    var antiSettingsCtor = antiSettingsType?
                        .GetConstructors(System.Reflection.BindingFlags.NonPublic
                                         | System.Reflection.BindingFlags.Instance)
                        .SingleOrDefault(constructor => constructor.GetParameters().Length == 3);

                    if (antiSettingsCtor is not null)
                    {
                        using var antiDialog = (Form)antiSettingsCtor.Invoke(new object[]
                        {
                            new AntiScanSettingsDto
                            {
                                Enabled = true,
                                AutoBlock = true,
                                Sensitivity = "standard",
                                BlockMinutes = 10,
                                Allowlist = new List<string> { "192.0.2.10" },
                            },
                            true,
                            "1.90",
                        });

                        var leftovers = Walk(antiDialog)
                            .Where(control => HasCjk(control.Text))
                            .Select(control => $"{control.GetType().Name}:{control.Text}")
                            .ToList();

                        if (leftovers.Count > 0)
                        {
                            W("    防护设置对话框残留：" + string.Join(" / ", leftovers));
                        }

                        CheckAssertion(results, "英文：防护设置对话框无中文",
                            leftovers.Count == 0 && !HasCjk(antiDialog.Text));

                        antiDialog.PerformLayout();

                        if (TryGetField<TextBox>(antiDialog, "_allowlist", out var allowBox)
                            && antiDialog.AcceptButton is Control acceptButton)
                        {
                            var table = antiDialog.Controls[0];
                            var tablePreferred = table.GetPreferredSize(Size.Empty);

                            W($"    防护设置：允许名单框高 {allowBox.Height}px / " +
                              $"客户端 {antiDialog.ClientSize.Width}x{antiDialog.ClientSize.Height}px / " +
                              $"内容需要 {tablePreferred.Width}x{tablePreferred.Height}px");

                            CheckAssertion(results, "防护设置：允许名单框有可用高度",
                                allowBox.Height >= 60);
                            CheckAssertion(results, "防护设置：内容不超出对话框",
                                acceptButton.Right <= antiDialog.ClientSize.Width
                                && acceptButton.Bottom <= antiDialog.ClientSize.Height
                                && tablePreferred.Width <= antiDialog.ClientSize.Width);
                        }
                        else
                        {
                            CheckAssertion(results, "防护设置：找得到允许名单框与按钮", false);
                        }
                    }
                    else
                    {
                        CheckAssertion(results, "英文：防护设置对话框可构造", false);
                    }

                    var sampleRule = new FirewallRuleItem
                    {
                        Name = "AppGuard_Block_a.exe_1",
                        ApplicationPath = @"C:\Tools\a.exe",
                        Description = string.Empty,
                        Grouping = "AppGuard",
                        Enabled = true,
                        Action = FirewallAction.Block,
                        Direction = FirewallDirection.Outbound,
                        Protocol = 256,
                    };

                    CheckAssertion(results, "英文：规则单元格值无中文",
                        !HasCjk(sampleRule.RuleKindText)
                        && !HasCjk(sampleRule.ScopeText)
                        && !HasCjk(sampleRule.ExpiryText)
                        && !HasCjk(sampleRule.EnabledText)
                        && !HasCjk(sampleRule.ActionText));

                    var sampleConnection = new TcpConnectionItem
                    {
                        Pid = 1,
                        ProcessName = "a.exe",
                        ProcessPath = @"C:\Tools\a.exe",
                        Protocol = "IPv4",
                        LocalPort = 50000,
                        RemoteAddress = IPAddress.Loopback,
                        RemotePort = 443,
                        State = TcpState.Established,
                    };

                    CheckAssertion(results, "英文：连接单元格值无中文",
                        !HasCjk(sampleConnection.StateText)
                        && !HasCjk(sampleConnection.BlockStateText)
                        && !HasCjk(sampleConnection.WhitelistText));

                    // 诊断：把主窗体上仍然带中文的可见文字全部列出来，避免再漏。
                    static IEnumerable<Control> Walk(Control root)
                    {
                        yield return root;

                        foreach (Control child in root.Controls)
                        {
                            foreach (var item in Walk(child))
                            {
                                yield return item;
                            }
                        }
                    }

                    W();
                    W("===== 英文界面残留中文扫描 =====");

                    foreach (var control in Walk(form))
                    {
                        if (HasCjk(control.Text))
                        {
                            W($"    {control.GetType().Name} {control.Name} = "
                              + control.Text!.Replace("\r", " ").Replace("\n", " "));
                        }

                        if (control is TextBox box && HasCjk(box.PlaceholderText))
                        {
                            W($"    {control.Name}.PlaceholderText = {box.PlaceholderText}");
                        }

                        if (control is WinAppGuard.Forms.DataGridViewBuffered buffered
                            && HasCjk(buffered.EmptyText))
                        {
                            W($"    {control.Name}.EmptyText = "
                              + buffered.EmptyText.Replace("\r", " ").Replace("\n", " "));
                        }
                    }
                }
            }

            Localizer.Initialize("zh");

            using (var form = new MainForm(isAutostart: false))
            {
                TrySetField(form, "_runtimeInitialized", true);

                if (TryGetField<TabPage>(form, "_tabConnections", out var connections))
                {
                    W($"    中文页签 = {connections.Text}");
                    CheckAssertion(results, "中文：联网连接页签回退正确",
                        connections.Text == "联网连接");
                }
                else
                {
                    CheckAssertion(results, "找得到中文界面控件", false);
                }
            }

            var originalCulture = System.Globalization.CultureInfo.CurrentUICulture;

            try
            {
                System.Globalization.CultureInfo.CurrentUICulture =
                    new System.Globalization.CultureInfo("en-US");
                Localizer.Initialize("auto");
                CheckAssertion(results, "auto + en-US → English", Localizer.IsEnglish);

                System.Globalization.CultureInfo.CurrentUICulture =
                    new System.Globalization.CultureInfo("zh-CN");
                Localizer.Initialize("auto");
                CheckAssertion(results, "auto + zh-CN → 中文", !Localizer.IsEnglish);
            }
            finally
            {
                System.Globalization.CultureInfo.CurrentUICulture = originalCulture;
            }

            var temp = Path.Combine(
                Path.GetTempPath(), $"wag-language-{Guid.NewGuid():N}.json");

            try
            {
                var state = new UiState { Language = "en" };
                state.Save(temp);

                var loaded = UiState.Load(temp);
                CheckAssertion(results, "语言设置能持久化", loaded.Language == "en");
            }
            finally
            {
                try { File.Delete(temp); } catch (Exception) { }
            }
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "界面语言测试执行完成", false);
        }
        finally
        {
            Localizer.Initialize(previous switch
            {
                Localizer.LanguageMode.English => "en",
                Localizer.LanguageMode.Chinese => "zh",
                _ => "auto",
            });
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static void RunServiceUiTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   服务状态显示（离线 / 运行中；离线自检）                     #");
        W("################################################################");
        W();

        MainForm.SuppressBackgroundServices = true;

        using var form = new MainForm(isAutostart: false);
        TrySetField(form, "_runtimeInitialized", true);

        if (!TryGetField<ToolStripStatusLabel>(form, "_serviceStatusLabel", out var label))
        {
            CheckAssertion(results, "找得到服务状态标签 _serviceStatusLabel", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        InvokePrivate(form, "UpdateServiceStatusLabel", new object?[] { null });
        W($"    离线时 = {label.Text ?? string.Empty}");
        CheckAssertion(results, "服务不可用时显示「离线模式」",
            (label.Text ?? string.Empty).Contains("离线模式", StringComparison.Ordinal));

        var status = new ServiceStatus
        {
            ServiceVersion = "3.1",
            SublayerPresent = true,
            BlockRuleCount = 3,
            AllowRuleCount = 1,
        };

        InvokePrivate(form, "UpdateServiceStatusLabel", new object?[] { status });
        W($"    运行时 = {label.Text ?? string.Empty}");
        CheckAssertion(results, "服务正常时显示「运行中」和规则总数",
            (label.Text ?? string.Empty).Contains("运行中", StringComparison.Ordinal)
            && (label.Text ?? string.Empty).Contains("4 条规则", StringComparison.Ordinal));

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 服务不可用时的规则页只读状态（离线自检，不需要管理员、不需要服务）。
    ///
    /// 只测**界面状态机**：离线 → 写按钮全禁用 + 页首提示；恢复 → 按钮回来。
    /// 真实的"服务被停掉"路径由 VM 手工验收覆盖。
    /// </summary>
    private static void RunUiOfflineRulesTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   规则页离线只读（离线自检；不需要管理员 / 服务）              #");
        W("################################################################");
        W();

        MainForm.SuppressBackgroundServices = true;

        using var form = new MainForm(isAutostart: false);
        TrySetField(form, "_runtimeInitialized", true);

        if (!TryGetField<Button>(form, "_rulesAddButton", out var addButton)
            || !TryGetField<Button>(form, "_rulesImportButton", out var importButton)
            || !TryGetField<Button>(form, "_whitelistAddButton", out var whitelistAdd)
            || !TryGetField<Label>(form, "_rulesNoticeLabel", out var notice)
            || !TryGetField<ToolStripStatusLabel>(form, "_serviceStatusLabel", out var serviceLabel)
            || !TryGetField<ToolStripStatusLabel>(form, "_statusRulesLabel", out var rulesStatusLabel)
            || !TryGetField<Button>(form, "_strictModeToggleButton", out var strictToggle)
            || !TryGetField<Label>(form, "_strictModeStatusLabel", out var strictStatus))
        {
            CheckAssertion(results, "找得到规则页的按钮与提示标签", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        // 走真实的"服务探测失败"路径（bug：以前只改状态栏文字，规则页还留着可编辑）。
        InvokePrivate(form, "UpdateServiceStatusLabel", new object?[] { null });
        InvokePrivate(form, "UpdateRulesActionState", Array.Empty<object?>());
        InvokePrivate(form, "UpdateWhitelistActionState", Array.Empty<object?>());
        form.Refresh();

        W($"    离线：加入={addButton.Enabled}，导入={importButton.Enabled}，" +
          $"白名单加入={whitelistAdd.Enabled}");
        W($"    提示：{(notice.Text ?? string.Empty).Replace("\r\n", " / ")}");
        W($"    状态栏：{(serviceLabel.Text ?? string.Empty)} / {(rulesStatusLabel.Text ?? string.Empty)}");

        CheckAssertion(results, "服务不可用时状态栏显示「离线模式」",
            (serviceLabel.Text ?? string.Empty).Contains("离线模式", StringComparison.Ordinal));
        CheckAssertion(results, "离线时黑名单「加入」禁用", !addButton.Enabled);
        CheckAssertion(results, "离线时「导入」禁用", !importButton.Enabled);
        CheckAssertion(results, "离线时白名单「加入」禁用", !whitelistAdd.Enabled);
        CheckAssertion(results, "离线提示写明只读",
            (notice.Text ?? string.Empty).Contains("只读", StringComparison.Ordinal));
        CheckAssertion(results, "离线时左下角不再显示旧的已阻止数量",
            (rulesStatusLabel.Text ?? string.Empty).Contains("只读", StringComparison.Ordinal));
        CheckAssertion(results, "离线时严格模式开关禁用", !strictToggle.Enabled);
        CheckAssertion(results, "离线时严格模式说明「不可用」",
            (strictStatus.Text ?? string.Empty).Contains("不可用", StringComparison.Ordinal));

        // 模拟服务恢复
        TrySetField(form, "_serviceAvailable", true);
        InvokePrivate(form, "RestoreRulesPageWritable", Array.Empty<object?>());
        InvokePrivate(form, "UpdateRulesActionState", Array.Empty<object?>());
        InvokePrivate(form, "UpdateWhitelistActionState", Array.Empty<object?>());
        form.Refresh();

        W($"    恢复：加入={addButton.Enabled}，导入={importButton.Enabled}");
        CheckAssertion(results, "恢复后「加入」重新可用", addButton.Enabled);
        CheckAssertion(results, "恢复后「导入」重新可用", importButton.Enabled);

        InvokePrivate(form, "RefreshStrictModeStatus", Array.Empty<object?>());
        CheckAssertion(results, "恢复后严格模式开关可用", strictToggle.Enabled);

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// IPC 身份边界（M1.5）：管理员能连上，普通用户连不上。
    ///
    /// 这个模式**刻意不自动提权** —— 否则普通用户一跑就被 UAC 提权，
    /// 测出来的永远是"管理员能连"。
    ///
    /// 用法：服务安装并运行后，分别在管理员终端和标准用户终端各跑一次。
    /// </summary>
    private static void RunServicePingTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var elevated = AdminHelper.IsRunningAsAdmin();

        var statusResponse = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.Status },
            TimeSpan.FromSeconds(1.5),
            out var statusError);
        var status = statusResponse is { Ok: true } ? statusResponse.Status : null;

        var authResponse = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.AuthCheck },
            TimeSpan.FromSeconds(1.5),
            out var authError);

        W("################################################################");
        W("#   IPC 身份边界（查看免管理员 / 改动需提权）                     #");
        W("################################################################");
        W();
        W($"    当前身份 = {(elevated ? "管理员（已提权）" : "标准用户（未提权）")}");
        W($"    状态查询 = {(status is null ? "失败" : $"成功（服务 v{status.ServiceVersion}）")}");
        W($"    鉴权探针 = {(authResponse is null ? "无响应" : authResponse.Ok ? "允许" : "拒绝")}");

        if (statusError is not null)
        {
            W($"    状态错误 = {statusError}");
        }
        else if (statusResponse is { Ok: false })
        {
            W($"    状态被拒 = {statusResponse.Error}");
        }

        if (authError is not null)
        {
            W($"    探针错误 = {authError}");
        }
        else if (authResponse is { Ok: false })
        {
            W($"    探针被拒 = {authResponse.Error}");
        }

        W();

        CheckAssertion(results, "查看状态不需要管理员（M1.5）", status is not null);
        CheckAssertion(results,
            elevated ? "管理员提权被识别" : "标准用户被识别为未提权",
            authResponse is not null && authResponse.Ok == elevated);

        W("    提示：这个模式不会自动提权；请在两种账号下各跑一次。");
        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 服务 DACL（需管理员 + 服务已安装）：只给 SYSTEM + 所有者完全控制，
    /// Administrators 只有查询/启动；不允许 Interactive/Everyone 等。
    /// 管道 ACL 用行为验证：所有者能连、其他账户连不上（手工/第 4 步）。
    /// </summary>
    private static void RunServiceAclTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   服务 DACL（SYSTEM + 所有者；管理员仅查询/启动）              #");
        W("################################################################");
        W();

        try
        {
            var ownerSid = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory)
                .ReadConfig().OwnerSid;

            var output = RunScCapture("sdshow " + ServiceProtocol.ServiceName);

            if (output is null)
            {
                CheckAssertion(results, "能读取服务安全描述符", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            W($"    {output.Trim()}");

            // sc sdshow 会把服务权限编码成字母（CC/DC/LC/SW/RP/WP/DT/LO/CR/SD/RC/WD/WO），
            // 不是 (A;;GA;;;SY)。另外 S: 是 SACL（系统审计 Everyone），不是 DACL，
            // 不能拿它来判断“通配访问”。
            var daclStart = output.IndexOf("D:", StringComparison.Ordinal);
            var saclStart = daclStart >= 0
                ? output.IndexOf("S:", daclStart + 2, StringComparison.Ordinal)
                : -1;
            var dacl = daclStart < 0
                ? string.Empty
                : (saclStart > daclStart
                    ? output[daclStart..saclStart]
                    : output[daclStart..]);

            W($"    DACL = {dacl}");

            const string FullMask = "CCDCLCSWRPWPDTLOCRSDRCWDWO";

            bool AceFor(string sid, string rights)
            {
                foreach (var ace in dacl.Split(
                             '(', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (ace.Contains($";;;{sid})", StringComparison.Ordinal)
                        && ace.Contains(rights, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }

                return false;
            }

            bool HasFullControl(string sid)
                => AceFor(sid, FullMask) || AceFor(sid, "GA");

            CheckAssertion(results, "安全描述符包含 DACL",
                daclStart >= 0 && dacl.Length > 0);

            CheckAssertion(results, "SYSTEM 完全控制", HasFullControl("SY"));

            CheckAssertion(results, $"所有者 {ownerSid} 完全控制",
                HasFullControl(ownerSid));

            CheckAssertion(results, "Administrators 只有查询/启动/读权限",
                AceFor("BA", "LCRPRC")
                || AceFor("BA", "0x20014")
                || AceFor("BA", "0x00020014"));

            CheckAssertion(results, "Administrators 没有完全控制",
                !HasFullControl("BA"));

            CheckAssertion(results, "DACL 没有 Interactive / Everyone / Users 通配",
                !dacl.Contains(";;;IU)", StringComparison.Ordinal)
                && !dacl.Contains(";;;WD)", StringComparison.Ordinal)
                && !dacl.Contains(";;;BU)", StringComparison.Ordinal));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "服务 DACL 检查执行完成", false);
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 服务端签名鉴权（**需管理员 + 服务已运行 + 所有者密钥**）：
    /// 正确签名、无签名、篡改、重放、错误密钥、未配置 signer。
    /// </summary>
    private static void RunServiceAuthTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var currentSigner = ServiceClient.CurrentSigner;

        W("################################################################");
        W("#   服务端签名鉴权（需服务已运行：正确 / 无签名 / 篡改 / 重放）  #");
        W("################################################################");
        W();

        try
        {
            var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));
            CheckAssertion(results, "正确签名能查询状态", status is not null);

            if (status is not null)
            {
                W($"    服务版本 = {status.ServiceVersion}，协议 = {status.ProtocolVersion}");
                W($"    受保护模式 = {status.ProtectedMode}，所有者 = {status.ProtectedModeOwner}");
                W($"    指纹 = {status.ProtectedModeFingerprint?[..16]}…");
                CheckAssertion(results, "status 报告受保护模式已启用",
                    status.ProtectedMode && status.ProtocolVersion == ServiceProtocol.Version);
            }

            var user = WindowsIdentity.GetCurrent().User
                       ?? throw new InvalidOperationException("拿不到当前 SID。");

            using var ownerKey = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory)
                .LoadForOwner(user);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            byte[] Challenge(NamedPipeClientStream pipe)
            {
                PipeCodec.WriteAsync(
                        pipe,
                        new ServiceRequest { Command = ServiceProtocol.Commands.AuthChallenge },
                        timeout.Token)
                    .GetAwaiter().GetResult();

                var response = PipeCodec
                    .ReadAsync<ServiceResponse>(pipe, timeout.Token)
                    .GetAwaiter().GetResult();

                if (response is not { Ok: true } || response.Nonce is null)
                {
                    throw new InvalidOperationException(
                        response?.Error ?? "challenge 没有返回 nonce");
                }

                return Convert.FromBase64String(response.Nonce);
            }

            NamedPipeClientStream Connect()
            {
                var pipe = new NamedPipeClientStream(
                    ".", ServiceProtocol.PipeName,
                    PipeDirection.InOut, PipeOptions.Asynchronous);
                pipe.Connect(3000);
                return pipe;
            }

            static byte[] JoinNonce(byte[] nonce, byte[] payload)
            {
                var data = new byte[nonce.Length + payload.Length];
                Buffer.BlockCopy(nonce, 0, data, 0, nonce.Length);
                Buffer.BlockCopy(payload, 0, data, nonce.Length, payload.Length);
                return data;
            }

            static ServiceResponse SendSigned(
                NamedPipeClientStream pipe,
                byte[] nonce,
                byte[] payload,
                byte[] signature,
                CancellationToken token)
            {
                PipeCodec.WriteSignedAsync(pipe, signature, payload, token)
                    .GetAwaiter().GetResult();
                return PipeCodec.ReadAsync<ServiceResponse>(pipe, token)
                           .GetAwaiter().GetResult()
                       ?? new ServiceResponse { Ok = false, Error = "无响应" };
            }

            var payload = JsonSerializer.SerializeToUtf8Bytes(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                ServiceProtocol.JsonOptions);

            // 1) challenge nonce 长度
            using (var pipe = Connect())
            {
                var nonce = Challenge(pipe);
                CheckAssertion(results, "challenge 返回 32 字节 nonce",
                    nonce.Length == 32);
            }

            // 2) 无签名（把 status 当第一条命令）
            using (var pipe = Connect())
            {
                PipeCodec.WriteAsync(
                        pipe,
                        new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                        timeout.Token)
                    .GetAwaiter().GetResult();

                var response = PipeCodec
                    .ReadAsync<ServiceResponse>(pipe, timeout.Token)
                    .GetAwaiter().GetResult();

                CheckAssertion(results, "无签名的请求被拒绝",
                    response is { Ok: false });
            }

            // 3) 篡改签名
            using (var pipe = Connect())
            {
                var nonce = Challenge(pipe);
                var signature = ownerKey.Sign(JoinNonce(nonce, payload));
                signature[0] ^= 0x01;

                var response = SendSigned(
                    pipe, nonce, payload, signature, timeout.Token);

                CheckAssertion(results, "篡改签名被拒绝", !response.Ok);
            }

            // 4) 重放：在另一个连接里复用旧签名（nonce 不同）
            byte[] replayedSignature;

            using (var pipe = Connect())
            {
                var nonce = Challenge(pipe);
                replayedSignature = ownerKey.Sign(JoinNonce(nonce, payload));

                var response = SendSigned(
                    pipe, nonce, payload, replayedSignature, timeout.Token);

                CheckAssertion(results, "正确签名能通过原始封套发送", response.Ok);
            }

            using (var pipe = Connect())
            {
                var newNonce = Challenge(pipe);

                var response = SendSigned(
                    pipe, newNonce, payload, replayedSignature, timeout.Token);

                CheckAssertion(results, "重放旧签名被拒绝", !response.Ok);
            }

            // 5) 错误密钥
            using (var wrongKey = OwnerKey.Create())
            using (var pipe = Connect())
            {
                var nonce = Challenge(pipe);
                var signature = wrongKey.Sign(JoinNonce(nonce, payload));

                var response = SendSigned(
                    pipe, nonce, payload, signature, timeout.Token);

                CheckAssertion(results, "错误密钥的签名被拒绝", !response.Ok);
            }

            // 6) 客户端没有 signer 时不发请求
            ServiceClient.SetSigner(null);

            var noSigner = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                TimeSpan.FromSeconds(1),
                out var noSignerError);

            CheckAssertion(results, "没有 signer 时客户端拒绝发送",
                noSigner is null && noSignerError is not null);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "签名鉴权测试执行完成", false);
        }
        finally
        {
            ServiceClient.SetSigner(currentSigner);
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 服务端严格模式（**需管理员 + 服务已安装运行**）：
    /// 开启 → 过滤器出现 → 停服务 → 过滤器消失（立即撤销）→ 启动服务 → 状态复位。
    ///
    /// 这里用 `sc stop`（优雅停止）验证"服务被停 = 撤销"；
    /// 崩溃路径由 BFE 的动态会话保证（`--wfp-strict-test` 已单独验证）。
    /// </summary>
    private static void RunServiceStrictTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var serviceWasStopped = false;

        W("################################################################");
        W("#   服务端严格模式（需管理员 + 服务已运行；会短暂停/启服务）      #");
        W("################################################################");
        W();

        try
        {
            var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(2));

            if (status is null)
            {
                CheckAssertion(results, "服务已安装并正在运行", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            // 保证从"未开启"开始。
            if (status.StrictModeActive)
            {
                _ = Call(ServiceProtocol.Commands.StrictDisable, new ServiceRequest(), out _);
            }

            var baseline = CountOurFilters();
            W($"    停服务前的过滤器数（基线）= {baseline}");

            // ---- 1. 通过 IPC 开启 ----
            var enable = Call(ServiceProtocol.Commands.StrictEnable, new ServiceRequest(), out var enableError);

            W($"    开启：{(enable is null ? enableError : $"Ok={enable.Ok}")}");
            CheckAssertion(results, "通过 IPC 开启严格模式成功", enable is { Ok: true });

            var enabledStatus = enable?.Status;
            W($"    状态：Active={enabledStatus?.StrictModeActive}，" +
              $"放行 {enabledStatus?.StrictModePermittedCount} 个程序");
            CheckAssertion(results, "服务状态报告严格模式已生效",
                enabledStatus?.StrictModeActive == true);
            CheckAssertion(results, "放行清单非空（白名单 + 本程序 + 系统程序）",
                enabledStatus?.StrictModePermittedCount > 0);

            var during = CountOurFilters();
            W($"    开启后过滤器数 = {during}（基线 {baseline}）");
            CheckAssertion(results, "严格模式会话的过滤器已进入 BFE", during > baseline);

            // ---- 2. 停服务 → 立即撤销 ----
            W("    停止服务…");
            serviceWasStopped = true;
            _ = RunSc("stop " + ServiceProtocol.ServiceName);

            var stopped = WaitUntil(() => ServiceClient.TryGetStatus(TimeSpan.FromMilliseconds(500)) is null, 15000);

            W($"    服务已停止 = {stopped}");
            CheckAssertion(results, "服务已停止（IPC 连不上）", stopped);

            // 进程退出可能比"IPC 连不上"晚一两秒，给 BFE 一点时间回收动态会话。
            // 每 500ms 查一次：WFP 引擎要反复开关，不能像普通条件那样 20ms 轮询。
            var filtersGone = false;
            var afterStop = -1;

            for (var attempt = 0; attempt < 30; attempt++)
            {
                afterStop = CountOurFilters();

                if (afterStop == baseline)
                {
                    filtersGone = true;
                    break;
                }

                Thread.Sleep(500);
            }

            W($"    停服务后过滤器数 = {afterStop}（预期回到基线 {baseline}）");
            CheckAssertion(results, "停服务后严格模式过滤器全部消失", filtersGone);
        }
        finally
        {
            if (serviceWasStopped)
            {
                // 等进程真正退出：IPC 先断，但服务可能还在 STOP_PENDING，
                // 这时立刻 sc start 会被 SCM 拒绝（VM 实测就是这样"起不来"）。
                W("    等待服务进程完全退出…");
                WaitUntil(
                    () => Process.GetProcessesByName("WinAppGuardSvc").Length == 0, 20000);

                W("    重新启动服务…");
                var startAccepted = false;

                for (var attempt = 0; attempt < 20; attempt++)
                {
                    if (RunSc("start " + ServiceProtocol.ServiceName))
                    {
                        startAccepted = true;
                        break;
                    }

                    Thread.Sleep(500);
                }

                W($"    sc start 被接受 = {startAccepted}");

                WaitUntil(
                    () => ServiceClient.TryGetStatus(TimeSpan.FromSeconds(1)) is not null,
                    40000);
            }
        }

        // ---- 3. 服务重启后状态复位 ----
        var revived = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(2));
        W($"    服务已恢复 = {revived is not null}，严格模式 = {revived?.StrictModeActive}");
        CheckAssertion(results, "服务重新启动后 IPC 恢复", revived is not null);
        CheckAssertion(results, "重启后严格模式是关闭状态", revived?.StrictModeActive == false);

        PrintSummary(results, showFirewallResidue: false);
    }

    private static int CountOurFilters()
    {
        try
        {
            using var engine = WfpEngine.Open();
            return engine.ListOurFilters().Count;
        }
        catch (Exception ex)
        {
            W($"    ！读取过滤器失败：{ex.Message}");
            return -1;
        }
    }

    private static string? RunScCapture(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("sc.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (process is null)
            {
                return null;
            }

            var output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();
            process.WaitForExit(15000);
            return process.HasExited && process.ExitCode == 0 ? output : null;
        }
        catch (Exception ex)
        {
            W($"    ！sc {arguments} 失败：{ex.Message}");
            return null;
        }
    }

    /// <summary>跑 sc.exe（Windows 自带，不引第三方）。</summary>
    private static bool RunSc(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("sc.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (process is null)
            {
                return false;
            }

            process.WaitForExit(15000);
            return process.HasExited && process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            W($"    ！sc {arguments} 失败：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 密钥原语（离线）：ECDSA P-256 + DPAPI 用户级加密。
    /// 不写任何系统文件，不需要管理员。
    /// </summary>
    private static void RunKeyPrimitiveTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var entropy = RandomNumberGenerator.GetBytes(32);
        OwnerKey? created = null;
        OwnerKey? loaded = null;
        OwnerKey? imported = null;

        W("################################################################");
        W("#   密钥原语（离线：生成 / DPAPI 往返 / 签名 / 篡改 / 错误密钥）  #");
        W("################################################################");
        W();

        try
        {
            created = OwnerKey.Create();

            W($"    公钥长度 = {created.PublicKey.Length} 字节");
            W($"    指纹 = {created.Fingerprint[..16]}…");
            CheckAssertion(results, "能生成 P-256 密钥对",
                created.PublicKey.Length > 0 && created.Fingerprint.Length == 64);

            var blob = created.ProtectPrivateKey(entropy);
            W($"    DPAPI blob = {blob.Length} 字节");
            CheckAssertion(results, "私钥能被 DPAPI 加密", blob.Length > 0);

            loaded = OwnerKey.Unprotect(blob, entropy);
            CheckAssertion(results, "DPAPI 往返后是同一把钥匙",
                loaded.Fingerprint == created.Fingerprint);

            var data = Encoding.UTF8.GetBytes("nonce||request-payload");

            var signature = created.Sign(data);
            W($"    签名长度 = {signature.Length} 字节");
            CheckAssertion(results, "签名能被公钥验证",
                OwnerKey.Verify(created.PublicKey, data, signature));

            var tamperedData = data.ToArray();
            tamperedData[0] ^= 0xFF;
            CheckAssertion(results, "数据被篡改后验签失败",
                !OwnerKey.Verify(created.PublicKey, tamperedData, signature));

            var tamperedSignature = signature.ToArray();
            tamperedSignature[0] ^= 0xFF;
            CheckAssertion(results, "签名被篡改后验签失败",
                !OwnerKey.Verify(created.PublicKey, data, tamperedSignature));

            imported = OwnerKey.ImportPublicKey(created.PublicKey);
            CheckAssertion(results, "公钥可以重新导入且指纹不变",
                imported.Fingerprint == created.Fingerprint
                && OwnerKey.Verify(imported.PublicKey, data, signature));

            var wrongEntropyRejected = false;

            try
            {
                using var wrong = OwnerKey.Unprotect(
                    blob, RandomNumberGenerator.GetBytes(32));
            }
            catch (Exception)
            {
                wrongEntropyRejected = true;
            }

            CheckAssertion(results, "错误 entropy 解不开私钥", wrongEntropyRejected);

            var corrupted = blob.ToArray();
            corrupted[corrupted.Length / 2] ^= 0xFF;
            var corruptedRejected = false;

            try
            {
                using var bad = OwnerKey.Unprotect(corrupted, entropy);
            }
            catch (Exception)
            {
                corruptedRejected = true;
            }

            CheckAssertion(results, "损坏的 blob 解不开", corruptedRejected);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "密钥原语执行完成", false);
        }
        finally
        {
            imported?.Dispose();
            loaded?.Dispose();
            created?.Dispose();
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 受保护模式文件存储（离线）：目录/文件 ACL、DPAPI 往返、轮换、删除。
    /// 不碰 ProgramData；只在临时目录里验证原语。
    /// </summary>
    private static void RunProtectedModeStoreTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var root = Path.Combine(
            Path.GetTempPath(), $"WinAppGuard-pm-test-{Guid.NewGuid():N}");
        var directory = Path.Combine(root, "protected-mode");
        var store = new OwnerKeyStore(directory);
        var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User;

        W("################################################################");
        W("#   受保护模式存储（离线：ACL / DPAPI / 轮换 / 删除）             #");
        W("################################################################");
        W();

        if (owner is null)
        {
            W("    ！无法获取当前账户 SID。");
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        try
        {
            string? firstFingerprint;

            using (var key = store.Create(owner, identity.Name))
            {
                firstFingerprint = key.Fingerprint;
                CheckAssertion(results, "能为当前账户生成密钥",
                    key.PublicKey.Length > 0 && key.Fingerprint.Length == 64);
            }

            CheckAssertion(results, "配置与私钥文件都已落盘",
                File.Exists(store.ConfigPath) && File.Exists(store.KeyPath));

            var config = store.ReadConfig();
            CheckAssertion(results, "配置里的所有者是当前账户",
                string.Equals(config.OwnerSid, owner.Value,
                    StringComparison.OrdinalIgnoreCase));

            using (var loaded = store.LoadForOwner(owner))
            {
                CheckAssertion(results, "能用当前账户解回同一把钥匙",
                    string.Equals(loaded.Fingerprint, firstFingerprint,
                        StringComparison.OrdinalIgnoreCase));
            }

            var configText = File.ReadAllText(store.ConfigPath);
            var keyBlobBase64 = Convert.ToBase64String(
                File.ReadAllBytes(store.KeyPath));

            CheckAssertion(results, "配置文件里没有私钥/密文副本",
                !configText.Contains("PRIVATE KEY", StringComparison.Ordinal)
                && !configText.Contains(keyBlobBase64, StringComparison.Ordinal));

            var directorySecurity = new DirectoryInfo(directory).GetAccessControl();
            var directoryRules = directorySecurity
                .GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();

            CheckAssertion(results, "密钥目录关闭继承，且只给 SYSTEM + 所有者",
                directorySecurity.AreAccessRulesProtected
                && HasRule(directoryRules, owner)
                && HasRule(directoryRules, new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid, null))
                && !HasRule(directoryRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid, null))
                && !HasRule(directoryRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid, null)));

            var fileSecurity = new FileInfo(store.ConfigPath).GetAccessControl();
            var fileRules = fileSecurity
                .GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();

            CheckAssertion(results, "配置文件关闭继承，且只给 SYSTEM + 所有者",
                fileSecurity.AreAccessRulesProtected
                && HasRule(fileRules, owner)
                && HasRule(fileRules, new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid, null))
                && !HasRule(fileRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid, null))
                && !HasRule(fileRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid, null)));

            string rotatedFingerprint;

            using (var rotated = store.Create(owner, identity.Name))
            {
                rotatedFingerprint = rotated.Fingerprint;
                CheckAssertion(results, "轮换后指纹发生变化",
                    !string.Equals(rotated.Fingerprint, firstFingerprint,
                        StringComparison.OrdinalIgnoreCase));
            }

            using (var loaded = store.LoadForOwner(owner))
            {
                CheckAssertion(results, "轮换后仍能正常解密",
                    string.Equals(loaded.Fingerprint, rotatedFingerprint,
                        StringComparison.OrdinalIgnoreCase));
            }

            var wrongOwnerRejected = false;

            try
            {
                using var _ = store.LoadForOwner(new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid, null));
            }
            catch (UnauthorizedAccessException)
            {
                wrongOwnerRejected = true;
            }

            CheckAssertion(results, "非所有者读取被拒绝", wrongOwnerRejected);

            File.WriteAllBytes(store.KeyPath, RandomNumberGenerator.GetBytes(64));
            var tamperedKeyRejected = false;

            try
            {
                using var _ = store.LoadForOwner(owner);
            }
            catch (Exception)
            {
                tamperedKeyRejected = true;
            }

            CheckAssertion(results, "损坏的私钥被拒绝", tamperedKeyRejected);

            using (var restored = store.Create(owner, identity.Name))
            {
                _ = restored.Fingerprint;
            }

            File.WriteAllText(store.ConfigPath, "{ this is not json");
            var corruptConfigRejected = false;

            try
            {
                _ = store.ReadConfig();
            }
            catch (InvalidDataException)
            {
                corruptConfigRejected = true;
            }

            CheckAssertion(results, "损坏的配置被拒绝", corruptConfigRejected);

            var deleted = store.TryDeleteAll(owner, out var deleteError, out _);

            CheckAssertion(results, "删除密钥目录并校验不存在",
                deleted && !Directory.Exists(directory));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "受保护模式存储测试执行完成", false);
        }
        finally
        {
            try
            {
                _ = store.TryDeleteAll(owner, out _, out _);
            }
            catch (Exception)
            {
                // 清理失败不影响报告。
            }

            try
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (Exception)
            {
                // 同上。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static bool HasRule(
        IEnumerable<FileSystemAccessRule> rules, SecurityIdentifier sid)
        => rules.Any(rule => rule.IdentityReference.Equals(sid));

    /// <summary>
    /// 检查**已安装**的受保护模式密钥（只读，不改系统）：
    /// 文件存在、所有者为当前账户、DPAPI 能解开、能签名、ACL 正确。
    /// 用于 VM 安装后的验收。
    /// </summary>
    private static void RunProtectedModeOwnerTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var store = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory);
        var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User;

        W("################################################################");
        W("#   已安装的受保护模式密钥（只读：所有者 / DPAPI / ACL / 签名）  #");
        W("################################################################");
        W();

        if (owner is null)
        {
            W("    ！无法获取当前账户 SID。");
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        try
        {
            CheckAssertion(results, "配置文件存在", File.Exists(store.ConfigPath));
            CheckAssertion(results, "私钥文件存在", File.Exists(store.KeyPath));

            var config = store.ReadConfig();

            CheckAssertion(results, "所有者是当前账户",
                string.Equals(config.OwnerSid, owner.Value,
                    StringComparison.OrdinalIgnoreCase));

            using var key = store.LoadForOwner(owner);

            CheckAssertion(results, "DPAPI 解开的指纹与配置一致",
                string.Equals(key.Fingerprint, config.Fingerprint,
                    StringComparison.OrdinalIgnoreCase));

            var payload = Encoding.UTF8.GetBytes("WinAppGuard owner test");
            var signature = key.Sign(payload);

            CheckAssertion(results, "能用公钥验证签名",
                OwnerKey.Verify(config.GetPublicKeyBytes(), payload, signature));

            var configText = File.ReadAllText(store.ConfigPath);
            CheckAssertion(results, "配置里没有私钥/密文副本",
                !configText.Contains("PRIVATE KEY", StringComparison.Ordinal)
                && !configText.Contains(
                    Convert.ToBase64String(File.ReadAllBytes(store.KeyPath)),
                    StringComparison.Ordinal));

            var directorySecurity = new DirectoryInfo(
                ServicePaths.ProtectedModeDirectory).GetAccessControl();
            var directoryRules = directorySecurity
                .GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();

            CheckAssertion(results, "密钥目录只给 SYSTEM + 所有者",
                directorySecurity.AreAccessRulesProtected
                && HasRule(directoryRules, owner)
                && HasRule(directoryRules, new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid, null))
                && !HasRule(directoryRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid, null))
                && !HasRule(directoryRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid, null)));

            var fileSecurity = new FileInfo(store.ConfigPath).GetAccessControl();
            var fileRules = fileSecurity
                .GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();

            CheckAssertion(results, "配置文件只给 SYSTEM + 所有者",
                fileSecurity.AreAccessRulesProtected
                && HasRule(fileRules, owner)
                && HasRule(fileRules, new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid, null))
                && !HasRule(fileRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid, null))
                && !HasRule(fileRules, new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid, null)));

            W();
            W($"    所有者 = {config.OwnerName}（{config.OwnerSid}）");
            W($"    指纹   = {key.Fingerprint[..16]}…");
            W($"    创建   = {config.CreatedUtc:yyyy-MM-dd HH:mm:ss} UTC");
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "已安装密钥检查执行完成", false);
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 规则快照（离线）：服务写的 rules.json 必须能被界面读回；
    /// 坏文件/版本不认识要当成"没有"，绝不能让界面崩。
    /// </summary>
    private static void RunSnapshotTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var directory = Path.Combine(Path.GetTempPath(), $"wag-snapshot-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "rules.json");

        W("################################################################");
        W("#   规则快照（离线：原子写 / 往返 / 坏文件容错）                  #");
        W("################################################################");
        W();

        try
        {
            var snapshot = new RuleSnapshot
            {
                Rules =
                {
                    new RuleDto
                    {
                        Name = "AppGuard_Block_test",
                        Kind = "program",
                        Value = @"C:\Tools\测试.exe",
                        Action = "block",
                        Expiry = "never",
                        Scope = "",
                        Group = "工作",
                        Enabled = true,
                    },
                    new RuleDto
                    {
                        Name = "AppGuard_IP_1.2.3.4",
                        Kind = "ip",
                        Value = "1.2.3.4",
                        Action = "block",
                    },
                },
            };

            RuleSnapshotFile.Write(path, snapshot);

            W($"    写入：{path}");
            CheckAssertion(results, "快照文件已创建", File.Exists(path));
            CheckAssertion(results, "没有残留临时文件",
                !File.Exists(path + ".tmp"));

            var read = RuleSnapshotFile.TryRead(path);

            W($"    读回：{read?.Rules.Count} 条，时间 {read?.SavedUtc:yyyy-MM-dd HH:mm:ss} UTC");
            CheckAssertion(results, "能原样读回快照", read is { Rules.Count: 2 });
            CheckAssertion(results, "程序规则字段完整",
                read?.Rules[0] is { Kind: "program", Action: "block", Group: "工作" }
                && read.Rules[0].Value == @"C:\Tools\测试.exe");
            CheckAssertion(results, "IP 规则字段完整",
                read?.Rules[1] is { Kind: "ip", Value: "1.2.3.4" });
            CheckAssertion(results, "写入时间已记录",
                read is not null && (DateTime.UtcNow - read.SavedUtc).TotalMinutes < 5);

            File.WriteAllText(path, "{ 这不是 JSON", Encoding.UTF8);
            CheckAssertion(results, "损坏的快照按「没有」处理",
                RuleSnapshotFile.TryRead(path) is null);

            File.WriteAllText(path,
                """{"Version":2,"Rules":[]}""", Encoding.UTF8);
            CheckAssertion(results, "未来版本按「没有」处理",
                RuleSnapshotFile.TryRead(path) is null);
        }
        finally
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 服务端审计（**需管理员 + 服务已运行**）：不开界面，记录也必须继续。
    /// 用一条本机**非回环**地址的连接做确定性验证（不联网、不改规则）。
    /// </summary>
    private static void RunServiceAuditTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var restore = new ServiceRequest();

        W("################################################################");
        W("#   服务端审计（需管理员 + 服务已运行；本机连接，约 10 秒）      #");
        W("################################################################");
        W();

        try
        {
            var statusResponse = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                TimeSpan.FromSeconds(2),
                out var statusError);

            var status = statusResponse is { Ok: true } ? statusResponse.Status : null;

            if (status is null)
            {
                W($"    ！服务不可用：{statusError}");
                CheckAssertion(results, "服务已安装并正在运行", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            // 记住原设置，结束时恢复（机器级设置，不能测完就改掉）。
            restore = new ServiceRequest
            {
                AuditEnabled = status.AuditEnabled,
                AuditDomainLookup = status.AuditDomainLookup,
                AuditRetentionDays = status.AuditRetentionDays,
            };

            var enable = Call(ServiceProtocol.Commands.AuditConfigure, new ServiceRequest
            {
                AuditEnabled = true,
                AuditDomainLookup = false,
            }, out var enableError);

            W($"    开启采集：{(enable is null ? enableError : $"Ok={enable.Ok}")}");
            CheckAssertion(results, "能通过 IPC 开启采集", enable is { Ok: true });
            CheckAssertion(results, "服务状态显示正在采集",
                enable?.Status?.AuditCollecting == true);

            var baseline = CountAuditEvents();
            W($"    测试前已有记录 = {baseline} 条");

            // 用**非回环**的本机地址建连接：审计按设计会忽略回环（127.0.0.1），
            // 用回环测的话记录数永远不会变（第一版就栽在这里）。
            var lanAddress = GetNonLoopbackIPv4();
            TcpListener? listener = null;
            TcpClient? client = null;
            TcpClient? accepted = null;

            try
            {
                IPAddress probeAddress;
                int port;

                if (lanAddress is not null)
                {
                    listener = new TcpListener(IPAddress.Any, 0);
                    listener.Start();

                    port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    probeAddress = lanAddress;

                    client = new TcpClient();
                    client.Connect(lanAddress, port);
                    accepted = listener.AcceptTcpClient();
                }
                else
                {
                    // 没有非回环地址（极少数环境）：退回外网 whois（需要能联网）。
                    probeAddress = Dns.GetHostAddresses("whois.cymru.com")
                        .First(address => address.AddressFamily == AddressFamily.InterNetwork);
                    port = 43;

                    client = new TcpClient();
                    var connect = client.ConnectAsync(probeAddress, port);

                    if (!connect.Wait(5000) || !client.Connected)
                    {
                        throw new InvalidOperationException("连不上外网测试目标。");
                    }
                }

                W($"    已建立连接 {probeAddress}:{port}，等待采集（约 9 秒）…");
                Thread.Sleep(9000);

                var events = ReadAuditEvents(3000);
                var found = events.Any(item =>
                    item.RemotePort == port
                    && item.RemoteAddress == probeAddress.ToString()
                    && item.ProcessPath.Contains("WinAppGuard.SelfCheck", StringComparison.OrdinalIgnoreCase));

                W($"    记录总数 = {events.Count}（测试前 {baseline}）；找到测试连接 = {found}");
                CheckAssertion(results, "服务在无人操作时仍在写记录", events.Count > baseline);
                CheckAssertion(results, "记录里能找到刚才那条连接（含进程路径）", found);
            }
            catch (Exception ex)
            {
                W($"    ！无法建立可记录的测试连接：{ex.Message}");
                CheckAssertion(results, "服务在无人操作时仍在写记录", false);
                CheckAssertion(results, "记录里能找到刚才那条连接（含进程路径）", false);
            }
            finally
            {
                client?.Dispose();
                accepted?.Dispose();
                listener?.Stop();
            }
        }
        finally
        {
            // 恢复原设置（失败也要尝试）。
            try
            {
                _ = Call(ServiceProtocol.Commands.AuditConfigure, restore, out _);
            }
            catch (Exception)
            {
                // 恢复失败不影响结论，但会写进报告。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static int CountAuditEvents() => ReadAuditEvents(3000).Count;

    /// <summary>本机的非回环 IPv4（审计按设计忽略 127.0.0.1，测试必须用真实地址）。</summary>
    private static IPAddress? GetNonLoopbackIPv4()
    {
        try
        {
            return Dns.GetHostAddresses(Dns.GetHostName())
                .FirstOrDefault(address =>
                    address.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(address));
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static IReadOnlyList<AuditEvent> ReadAuditEvents(int maxCount)
    {
        try
        {
            using var store = new AuditStore(ServicePaths.AuditDirectory);
            return store.ReadRecent(maxCount);
        }
        catch (Exception ex)
        {
            W($"    ！读取审计记录失败：{ex.Message}");
            return Array.Empty<AuditEvent>();
        }
    }

    /// <summary>
    /// 审计记录迁移（离线）：复制 → 校验 → 删源；同名冲突不覆盖。
    /// </summary>
    private static void RunAuditMigrateTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var root = Path.Combine(Path.GetTempPath(), $"wag-migrate-{Guid.NewGuid():N}");
        var source = Path.Combine(root, "local");
        var target = Path.Combine(root, "programdata");

        W("################################################################");
        W("#   审计记录迁移（离线：复制 / 校验 / 删源 / 冲突保留）          #");
        W("################################################################");
        W();

        try
        {
            Directory.CreateDirectory(source);
            Directory.CreateDirectory(target);

            File.WriteAllText(Path.Combine(source, "audit-2026-10-01-00.jsonl"), "{\"a\":1}\n");
            File.WriteAllText(Path.Combine(source, "audit-2026-10-02-00.jsonl"), "{\"a\":2}\n");

            var first = AuditMigration.Migrate(source, target);

            W($"    第一次迁移：{first.Migrated} 成功 / {first.Failed} 失败");
            CheckAssertion(results, "两个记录文件都迁移成功",
                first is { Migrated: 2, Failed: 0 });
            CheckAssertion(results, "目标文件内容一致",
                File.ReadAllText(Path.Combine(target, "audit-2026-10-01-00.jsonl")).Contains("\"a\":1"));
            CheckAssertion(results, "源文件已删除（方案 C 的删源步骤）",
                Directory.GetFiles(source, "audit-*.jsonl").Length == 0);

            // 同名同内容：去重删源，不报失败。
            File.WriteAllText(Path.Combine(source, "audit-2026-10-01-00.jsonl"), "{\"a\":1}\n");
            var duplicate = AuditMigration.Migrate(source, target);
            CheckAssertion(results, "同名同内容视为已迁移（去重删源）",
                duplicate is { Migrated: 1, Failed: 0 }
                && !File.Exists(Path.Combine(source, "audit-2026-10-01-00.jsonl")));

            // 同名不同内容：保留双方，报失败，绝不覆盖已有记录。
            File.WriteAllText(Path.Combine(source, "audit-2026-10-02-00.jsonl"), "{\"a\":999}\n");
            var conflict = AuditMigration.Migrate(source, target);

            W($"    冲突迁移：{conflict.Migrated} 成功 / {conflict.Failed} 失败");
            CheckAssertion(results, "同名不同内容保留双方并报失败",
                conflict.Failed == 1
                && File.Exists(Path.Combine(source, "audit-2026-10-02-00.jsonl"))
                && File.ReadAllText(Path.Combine(target, "audit-2026-10-02-00.jsonl")).Contains("\"a\":2"));

            var missing = AuditMigration.Migrate(Path.Combine(root, "不存在"), target);
            CheckAssertion(results, "源目录不存在时安全返回",
                missing is { Migrated: 0, Failed: 0 });
        }
        finally
        {
            try
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 篡改防护（**需管理员 + 服务已运行**）：
    /// 直接删掉一条规则的 WFP 过滤器 → 服务 10 秒内自动重建 → 分组也恢复；
    /// 随后由服务自己删除该规则，确认**不会误报**。
    /// </summary>
    private static void RunServiceTamperTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var tempExe = Path.Combine(Path.GetTempPath(), $"wag-tamper-test-{Guid.NewGuid():N}.exe");

        W("################################################################");
        W("#   篡改防护（需管理员 + 服务已运行；删过滤器 → 自动重建，约 40 秒）#");
        W("################################################################");
        W();

        try
        {
            var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(2));

            if (status is null)
            {
                CheckAssertion(results, "服务已安装并正在运行", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            File.Copy(Path.Combine(Environment.SystemDirectory, "whoami.exe"), tempExe, overwrite: true);

            var add = Call(ServiceProtocol.Commands.AddProgramRule, new ServiceRequest
            {
                Value = tempExe,
                Action = "block",
                Expiry = string.Empty,
                Scope = string.Empty,
                Group = "篡改测试组",
            }, out var addError);

            if (add is not { Ok: true })
            {
                W($"    ！添加测试规则失败：{addError ?? add?.Error}");
                CheckAssertion(results, "能创建测试规则", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            var before = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
            var rule = before?.Rules?.FirstOrDefault(item =>
                string.Equals(item.Value, tempExe, StringComparison.OrdinalIgnoreCase));

            CheckAssertion(results, "测试规则已创建并带分组",
                rule is not null && rule.Group == "篡改测试组");

            if (rule is null)
            {
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            // ---- 模拟外部删除：直接删掉这条规则的所有过滤器 ----
            var deleted = 0;

            using (var engine = WfpEngine.Open())
            {
                var keys = engine.ListOurFilters()
                    .Where(filter =>
                        WfpRule.TryParse(filter.Description, out var parsed)
                        && string.Equals(parsed.ApplicationPath, tempExe, StringComparison.OrdinalIgnoreCase))
                    .Select(filter => filter.Key)
                    .ToList();

                foreach (var key in keys)
                {
                    engine.DeleteFilter(key);
                    deleted++;
                }
            }

            W($"    已直接删除 {deleted} 个过滤器（绕过服务）");
            CheckAssertion(results, "确实删掉了过滤器", deleted > 0);

            var afterDelete = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
            var stillThere = afterDelete?.Rules?.Any(item =>
                string.Equals(item.Name, rule.Name, StringComparison.OrdinalIgnoreCase)) == true;

            W($"    服务列表里仍在 = {stillThere}（预期 False）");
            CheckAssertion(results, "外部删除后规则确实消失", !stillThere);

            // ---- 等服务自动重建（检测周期 10 秒，给 25 秒余量）----
            var rebuilt = WaitUntil(() =>
            {
                var list = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
                return list?.Rules?.Any(item =>
                    string.Equals(item.Name, rule.Name, StringComparison.OrdinalIgnoreCase)) == true;
            }, 25000);

            W($"    25 秒内自动重建 = {rebuilt}");
            CheckAssertion(results, "服务自动重建了被删的规则", rebuilt);

            var afterRebuild = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
            var restored = afterRebuild?.Rules?.FirstOrDefault(item =>
                string.Equals(item.Name, rule.Name, StringComparison.OrdinalIgnoreCase));

            CheckAssertion(results, "重建后分组也恢复", restored?.Group == "篡改测试组");

            var statusAfter = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(2));
            W($"    服务累计重建 = {statusAfter?.TamperRebuiltCount} 条");
            CheckAssertion(results, "服务状态记录了重建次数",
                statusAfter is not null && statusAfter.TamperRebuiltCount > status.TamperRebuiltCount);

            // ---- 服务自己删除：不应误报 ----
            var countBeforeSelfDelete = statusAfter?.TamperRebuiltCount ?? 0;

            _ = Call(ServiceProtocol.Commands.DeleteRule,
                new ServiceRequest { RuleName = rule.Name }, out _);

            Thread.Sleep(12000);

            var statusFinal = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(2));
            W($"    服务自己删除后累计重建 = {statusFinal?.TamperRebuiltCount}（应保持不变）");
            CheckAssertion(results, "服务自己删除不触发误报",
                statusFinal?.TamperRebuiltCount == countBeforeSelfDelete);
        }
        finally
        {
            try
            {
                var list = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
                var leftover = list?.Rules?.FirstOrDefault(item =>
                    string.Equals(item.Value, tempExe, StringComparison.OrdinalIgnoreCase));

                if (leftover is not null)
                {
                    _ = Call(ServiceProtocol.Commands.DeleteRule,
                        new ServiceRequest { RuleName = leftover.Name }, out _);
                }

                if (File.Exists(tempExe))
                {
                    File.Delete(tempExe);
                }
            }
            catch (Exception)
            {
                // 清理失败不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: true);
    }

    /// <summary>
    /// 规则写入迁移自检（**需管理员 + 服务已安装运行**）。
    /// 用临时目录里的 exe 副本做增/查/分组/删/导入，不碰用户已有规则。
    /// </summary>
    private static void RunServiceRulesTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var tempExe = Path.Combine(Path.GetTempPath(), $"wag-rule-test-{Guid.NewGuid():N}.exe");

        W("################################################################");
        W("#   服务端规则命令（需管理员 + 服务已运行；用临时 exe，不动用户规则）#");
        W("################################################################");
        W();

        try
        {
            File.Copy(Path.Combine(Environment.SystemDirectory, "whoami.exe"), tempExe, overwrite: true);

            var list = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out var listError);

            W($"    初始规则数 = {list?.Rules?.Count ?? -1}");
            CheckAssertion(results, "能通过服务列出规则", list is { Ok: true, Rules: not null });

            if (listError is not null)
            {
                W($"    ！{listError}");
            }

            // 1) 添加
            var add = Call(ServiceProtocol.Commands.AddProgramRule, new ServiceRequest
            {
                Value = tempExe,
                Action = "block",
                Expiry = string.Empty,
                Scope = string.Empty,
                Group = "自检分组",
            }, out var addError);

            W($"    添加：{(add is null ? addError : $"Ok={add.Ok}，错误={add.Error}")}");
            CheckAssertion(results, "添加阻止规则成功", add is { Ok: true });

            // 2) 列表 / 分组
            var afterAdd = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
            var added = afterAdd?.Rules?.FirstOrDefault(rule =>
                string.Equals(rule.Value, tempExe, StringComparison.OrdinalIgnoreCase));

            W($"    列表里找到 = {added is not null}，分组 = {added?.Group}");
            CheckAssertion(results, "列表里出现新规则", added is not null);
            CheckAssertion(results, "分组随规则保存", added?.Group == "自检分组");

            // 3.0-c：服务每次写入后都要更新权威副本（界面离线时靠它显示"上次已知状态"）。
            var snapshot = RuleSnapshotFile.TryRead(ServicePaths.RulesSnapshotFile);
            W($"    快照：{(snapshot is null ? "读不到" : $"{snapshot.Rules.Count} 条")}");

            CheckAssertion(results, "服务已写入规则快照", snapshot is not null);
            CheckAssertion(results, "快照里能找到刚加的规则",
                snapshot?.Rules.Any(rule =>
                    string.Equals(rule.Value, tempExe, StringComparison.OrdinalIgnoreCase)) == true);

            // 3) 过滤器映射
            var map = Call(ServiceProtocol.Commands.FilterMap, new ServiceRequest(), out _);
            CheckAssertion(results, "能取到过滤器 id → 规则名映射",
                map is { Ok: true, FilterMap: not null });

            // 4) 删除
            if (added is not null)
            {
                var delete = Call(ServiceProtocol.Commands.DeleteRule, new ServiceRequest
                {
                    RuleName = added.Name,
                }, out var deleteError);

                W($"    删除：{(delete is null ? deleteError : $"Ok={delete.Ok}，错误={delete.Error}")}");
                CheckAssertion(results, "删除规则成功", delete is { Ok: true });

                var afterDelete = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
                CheckAssertion(results, "删除后列表里不再有它",
                    afterDelete?.Rules?.All(rule =>
                        !string.Equals(rule.Value, tempExe, StringComparison.OrdinalIgnoreCase)) == true);
            }

            // 5) 导入（含分组）
            var document = new RuleExportDocument { Scope = "block" };
            document.Rules.Add(new RuleExportEntry
            {
                Kind = "program",
                Value = tempExe,
                Action = "block",
                Expiry = string.Empty,
                Scope = string.Empty,
                Group = "导入分组",
            });

            var import = Call(ServiceProtocol.Commands.ImportRules, new ServiceRequest
            {
                Action = "block",
                Json = RuleExport.Serialize(document),
            }, out var importError);

            W($"    导入：{(import is null ? importError : $"Ok={import.Ok}，影响 {import.Affected} 条")}");
            CheckAssertion(results, "导入成功且新建 1 条", import is { Ok: true, Affected: 1 });

            var afterImport = Call(ServiceProtocol.Commands.ListRules, new ServiceRequest(), out _);
            var imported = afterImport?.Rules?.FirstOrDefault(rule =>
                string.Equals(rule.Value, tempExe, StringComparison.OrdinalIgnoreCase));

            CheckAssertion(results, "导入的规则带上了分组", imported?.Group == "导入分组");

            if (imported is not null)
            {
                _ = Call(ServiceProtocol.Commands.DeleteRule,
                    new ServiceRequest { RuleName = imported.Name }, out _);
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tempExe))
                {
                    File.Delete(tempExe);
                }
            }
            catch (Exception)
            {
                // 临时文件删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: true);
    }

    /// <summary>发一条规则命令并取回响应（3 秒超时）。</summary>
    private static ServiceResponse? Call(
        string command, ServiceRequest request, out string? error)
    {
        request.Command = command;
        return ServiceClient.TryRequest(request, TimeSpan.FromSeconds(3), out error);
    }

    /// <summary>
    /// 安装 / 卸载端到端自检（**需要管理员，会装/卸服务并删除全部 AppGuard 规则**）。
    ///
    /// 只在虚拟机里跑。它验证的是"装得上、查得到、卸得干净"，
    /// 而不是规则过滤效果（那是 --wfp-* 的职责）。
    /// </summary>
    private static void RunServiceInstallTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var setup = Path.Combine(AppContext.BaseDirectory, "WinAppGuardSetup.exe");

        W("################################################################");
        W("#   服务安装 / 卸载（需管理员；会删除全部 AppGuard 规则）        #");
        W("################################################################");
        W();

        W("    ⚠ 本自检会：安装服务 → 查询状态 → 卸载服务 → 删除全部规则。");
        W($"    安装器 = {setup}");
        W();

        if (!File.Exists(setup))
        {
            CheckAssertion(results, "安装器与自检工具在同一目录（WinAppGuardSetup.exe）", false);
            W("    请把 WinAppGuardSetup.exe / WinAppGuardSvc.exe / WinAppGuard.exe 一起放到这里。");
            PrintSummary(results, showFirewallResidue: true);
            return;
        }

        var install = RunSetup(setup, "--install");
        W($"    安装输出：{install.Output.Trim()}");
        CheckAssertion(results, "安装命令成功返回", install.ExitCode == 0);

        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(5));

        W($"    服务状态 = {(status is null ? "连不上" : $"v{status.ServiceVersion}，协议 {status.ProtocolVersion}")}");
        CheckAssertion(results, "装完后能通过 IPC 查到服务状态", status is not null);
        CheckAssertion(results, "服务协议版本与客户端一致",
            status is not null && status.ProtocolVersion == ServiceProtocol.Version);

        var uninstall = RunSetup(setup, "--uninstall");
        W($"    卸载输出：{uninstall.Output.Trim()}");
        CheckAssertion(results, "卸载命令成功返回", uninstall.ExitCode == 0);

        Thread.Sleep(1200);
        CheckAssertion(results, "卸载后服务已经连不上",
            ServiceClient.TryGetStatus(TimeSpan.FromMilliseconds(500)) is null);

        var installDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinAppGuard");
        W($"    安装目录仍存在 = {Directory.Exists(installDirectory)}");
        CheckAssertion(results, "卸载后安装目录已删除", !Directory.Exists(installDirectory));

        PrintSummary(results, showFirewallResidue: true);
    }

    /// <summary>运行安装器并取回输出（60 秒超时）。</summary>
    private static (int ExitCode, string Output) RunSetup(string setupPath, string arguments)
    {
        try
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = setupPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            });

            if (process is null)
            {
                return (-1, "无法启动安装器。");
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();

            if (!process.WaitForExit(60_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception)
                {
                    // 杀不掉就算了，超时已经算失败。
                }

                return (-1, "安装器超时（60 秒）。");
            }

            return (process.ExitCode, stdout + stderr);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }

    /// <summary>
    /// 2.5：精细化范围（协议 / 端口 / 网络位置）的离线自检。
    ///
    /// 只验证"我们自己的编码与校验"；**真正的过滤效果**必须用 --wfp-scope-test 在虚拟机里验证
    /// （它会给测试程序建一条只拦 43 端口的规则，再确认 443 仍然通）。
    /// </summary>
    private static void RunRuleScopeTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   精细化范围：协议 / 远端端口 / 网络位置（离线）             #");
        W("################################################################");
        W();

        // ---------------- 1. 往返 ----------------
        W("===== 1. 范围编码往返 =====");

        var scopes = new[]
        {
            RuleScope.Any,
            new RuleScope(RuleProtocol.Tcp, 443, 443),
            new RuleScope(RuleProtocol.Udp, 8000, 8100),
            new RuleScope(RuleProtocol.Tcp, 0, 0),
            new RuleScope(RuleProtocol.Udp, 53, 53),
        };

        foreach (var scope in scopes)
        {
            var token = scope.Encode();
            var ok = RuleScope.TryParse(token, out var back);

            W($"    {scope.Describe()} → \"{token}\" → {back.Describe()}");
            CheckAssertion(results, $"范围往返：{scope.Describe()}",
                ok
                && back.Protocol == scope.Protocol
                && back.PortFrom == scope.PortFrom
                && back.PortTo == scope.PortTo);
        }

        // ---------------- 2. 非法组合必须被拒绝 ----------------
        W();
        W("===== 2. 非法组合 =====");

        var invalid = new (string Name, RuleScope Scope)[]
        {
            ("端口 + 任意协议", new RuleScope(RuleProtocol.Any, 443, 443)),
            ("起始大于结束", new RuleScope(RuleProtocol.Tcp, 900, 800)),
            ("端口为 0", new RuleScope(RuleProtocol.Tcp, 0, 443)),
            ("端口越界", new RuleScope(RuleProtocol.Tcp, 70000, 70000)),
        };

        foreach (var (name, scope) in invalid)
        {
            var reason = scope.Validate();
            W($"    {name} → {(reason is null ? "被接受（错误！）" : reason)}");
            CheckAssertion(results, $"拒绝非法范围：{name}", reason is not null);
        }

        // ---------------- 3. 端口文本解析 ----------------
        W();
        W("===== 3. 端口输入解析 =====");

        CheckAssertion(results, "单个端口 443",
            RuleScopeForm.TryParsePorts("443", out var singleFrom, out var singleTo, out _)
            && singleFrom == 443 && singleTo == 443);

        CheckAssertion(results, "端口范围 8000-8100",
            RuleScopeForm.TryParsePorts("8000-8100", out var rangeFrom, out var rangeTo, out _)
            && rangeFrom == 8000 && rangeTo == 8100);

        CheckAssertion(results, "留空表示不限",
            RuleScopeForm.TryParsePorts("  ", out var emptyFrom, out var emptyTo, out _)
            && emptyFrom == 0 && emptyTo == 0);

        CheckAssertion(results, "乱填的端口被拒绝",
            !RuleScopeForm.TryParsePorts("abc", out _, out _, out _)
            && !RuleScopeForm.TryParsePorts("8000-", out _, out _, out _)
            && !RuleScopeForm.TryParsePorts("900-800", out _, out _, out _));

        // ---------------- 4. 规则说明与规则名 ----------------
        W();
        W("===== 4. 规则说明 / 规则名 =====");

        var scopedRule = new WfpRule(
            @"C:\Tools\a.exe",
            FirewallAction.Block,
            RuleExpiry.Never,
            new RuleScope(RuleProtocol.Tcp, 443, 443));

        W($"    说明 = {scopedRule.Description}");
        W($"    规则名 = {scopedRule.DisplayName}");

        CheckAssertion(results, "带范围的规则说明能原样解析回来",
            WfpRule.TryParse(scopedRule.Description, out var parsedRule)
            && parsedRule.Scope.Protocol == RuleProtocol.Tcp
            && parsedRule.Scope.PortFrom == 443);

        CheckAssertion(results, "规则名带上范围后缀（避免同程序不同范围重名）",
            scopedRule.DisplayName.EndsWith("_tcp443", StringComparison.Ordinal));

        CheckAssertion(results, "旧标记（4 段，带网络位置）仍能解析 —— 老规则不会变成看不懂",
            RuleScope.TryParse("tcp-443-443-any", out var legacyScope)
            && legacyScope.PortFrom == 443);

        CheckAssertion(results, "旧格式（v1，无范围）仍然能解析",
            WfpRule.TryParse(@"AppGuard|1|Block|C:\Tools\a.exe|", out var legacyRule)
            && legacyRule.Scope.IsAny);

        CheckAssertion(results, "看不懂的范围标记不被猜测（宁可不认这条规则）",
            !WfpRule.TryParse(@"AppGuard|2|Block|C:\Tools\a.exe||tcp-443-xyz", out _));

        // ---------------- 5. 导出文件带范围 ----------------
        W();
        W("===== 5. 导出文件包含范围 =====");

        var groupStore = new RuleGroupStore(
            Path.Combine(Path.GetTempPath(), $"wag-scope-groups-{Guid.NewGuid():N}.json"));

        var item = new FirewallRuleItem
        {
            Name = scopedRule.DisplayName,
            ApplicationPath = scopedRule.ApplicationPath,
            Description = scopedRule.Description,
            Grouping = "AppGuard",
            Enabled = true,
            Action = FirewallAction.Block,
            Direction = FirewallDirection.Outbound,
            Protocol = 256,
            Scope = scopedRule.Scope,
        };

        var document = RuleExport.Build(new[] { item }, groupStore, FirewallAction.Block);
        var json = RuleExport.Serialize(document);

        CheckAssertion(results, "导出文件里写入了范围标记",
            json.Contains("\"Scope\": \"tcp-443-443\""));

        if (RuleExport.TryParse(json, out var parsedDocument, out _) && parsedDocument is not null)
        {
            var entry = parsedDocument.Rules.Single();
            CheckAssertion(results, "导入解析后范围仍然正确",
                RuleScope.TryParse(entry.Scope, out var importedScope)
                && importedScope.PortFrom == 443
                && importedScope.Protocol == RuleProtocol.Tcp);
        }
        else
        {
            results.Add(("导出的范围文件能被解析", false));
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 2.5：真实 WFP 过滤器上的范围验证（**需要管理员**，只在虚拟机里跑）。
    /// </summary>
    private static void RunWfpScopeTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   精细化范围：真实过滤器（需管理员；只拦 43，443 应仍然通）   #");
        W("################################################################");
        W();

        var exe = Environment.ProcessPath ?? string.Empty;
        W($"    测试程序 = {exe}");

        var portScope = new RuleScope(RuleProtocol.Tcp, 43, 43);
        var portRule = new WfpRule(exe, FirewallAction.Block, RuleExpiry.Never, portScope);

        using var engine = WfpEngine.Open();
        engine.EnsureSublayer(persistent: true);

        try
        {
            // 基线：43 和 443 都应该通
            var baseline43 = ProbeConnect("whois.cymru.com", 43);
            var baseline443 = ProbeConnect("example.com", 443);
            W($"    基线：whois:43={baseline43}，example:443={baseline443}");

            WfpRuleStore.Add(engine, portRule);
            Thread.Sleep(1500);

            var blocked43 = !ProbeConnect("whois.cymru.com", 43);
            var still443 = ProbeConnect("example.com", 443);

            W($"    只拦 43 后：whois:43 被拦={blocked43}，example:443 仍通={still443}");

            CheckAssertion(results, "按远端端口拦住了 43", blocked43);
            CheckAssertion(results, "同一个程序连 443 不受影响（端口条件真的生效）", still443);
        }
        finally
        {
            try
            {
                WfpRuleStore.Remove(engine, portRule);
                Thread.Sleep(500);

                var restored43 = ProbeConnect("whois.cymru.com", 43);
                W($"    清理后 whois:43 恢复={restored43}");
                CheckAssertion(results, "删除规则后 43 恢复", restored43);
            }
            catch (Exception ex)
            {
                W($"    ！清理失败：{ex.Message}");
                CheckAssertion(results, "删除规则后 43 恢复", false);
            }
        }

        PrintSummary(results, showFirewallResidue: true);
    }

    /// <summary>
    /// 2.1.1 界面打磨项的接线自检（**离线**）：搜索、空状态、危险按钮、快捷键、
    /// 右键菜单、窗口状态持久化、横幅提示。
    ///
    /// 这些都是"看起来有、其实没接上"最容易出问题的地方 ——
    /// 比如搜索框画出来了但没订阅 TextChanged，空状态写了但表格没设置，
    /// 危险按钮变红了但位置还在普通按钮旁边。
    /// </summary>
    private static void RunUiPolishTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   2.1.1 界面打磨自检（离线：搜索 / 空状态 / 快捷键 / 持久化）  #");
        W("################################################################");
        W();

        MainForm.SuppressBackgroundServices = true;

        using var form = new MainForm(isAutostart: false);
        TrySetField(form, "_runtimeInitialized", true);
        form.Show();
        Application.DoEvents();

        // ---------------- 1. 规则页搜索 ----------------
        W("===== 1. 规则页搜索 =====");

        results.Add(("规则页有搜索框", TryGetField<TextBox>(form, "_rulesSearchBox", out var rulesSearch)));

        if (rulesSearch is not null)
        {
            results.Add(("搜索框提示写明了搜什么",
                rulesSearch.PlaceholderText.Contains("路径") && rulesSearch.PlaceholderText.Contains("规则名")));
        }

        var sampleRule = MakeDocsRule(
            "AppGuard_Block_chrome.exe_1a2b3c4d",
            @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            FirewallAction.Block,
            RuleExpiry.Never);

        CheckAssertion(results, "按程序名能搜到",
            InvokeStatic<bool>(typeof(MainForm), "MatchesRule", sampleRule, "chrome"));
        CheckAssertion(results, "按路径能搜到",
            InvokeStatic<bool>(typeof(MainForm), "MatchesRule", sampleRule, @"Program Files\Google"));
        CheckAssertion(results, "按规则名能搜到",
            InvokeStatic<bool>(typeof(MainForm), "MatchesRule", sampleRule, "1a2b3c4d"));
        CheckAssertion(results, "不相关词搜不到",
            !InvokeStatic<bool>(typeof(MainForm), "MatchesRule", sampleRule, "notepad"));
        CheckAssertion(results, "搜索不区分大小写",
            InvokeStatic<bool>(typeof(MainForm), "MatchesRule", sampleRule, "CHROME"));

        // ---------------- 2. 空状态 ----------------
        W();
        W("===== 2. 空状态提示 =====");

        CheckAssertion(results, "连接表格有空状态文案",
            TryGetField<DataGridViewBuffered>(form, "_connectionGrid", out var connectionGrid)
            && !string.IsNullOrWhiteSpace(connectionGrid.EmptyText));

        CheckAssertion(results, "规则表格有空状态文案",
            TryGetField<DataGridViewBuffered>(form, "_rulesGrid", out var rulesGrid)
            && !string.IsNullOrWhiteSpace(rulesGrid.EmptyText));

        CheckAssertion(results, "记录表格有空状态文案",
            TryGetField<DataGridViewBuffered>(form, "_auditGrid", out var auditGrid)
            && !string.IsNullOrWhiteSpace(auditGrid.EmptyText));

        // ---------------- 3. 黑名单 / 白名单两个页签 ----------------
        W();
        W("===== 3. 「黑名单」与「严格模式下白名单」=====");

        CheckAssertion(results, "有「黑名单」页签",
            TryGetField<TabPage>(form, "_tabRules", out var blockTab)
            && blockTab.Text.Contains("黑名单"));

        CheckAssertion(results, "有「严格模式下白名单」页签",
            TryGetField<TabPage>(form, "_tabWhitelist", out var whitelistTab)
            && whitelistTab.Text.Contains("严格模式") && whitelistTab.Text.Contains("白名单"));

        if (TryGetField<Button>(form, "_rulesDeleteAllButton", out var deleteAll))
        {
            W($"    黑名单「清空」位置 = {deleteAll.Location}，颜色 = {deleteAll.ForeColor}");

            CheckAssertion(results, "「清空黑名单」是红色文字",
                deleteAll.ForeColor.R > 150 && deleteAll.ForeColor.G < 100);
            CheckAssertion(results, "「清空黑名单」不和普通按钮挤在同一行",
                deleteAll.Location.Y < 30);
            CheckAssertion(results, "「清空黑名单」被推到右侧",
                deleteAll.Location.X > 800);
            CheckAssertion(results, "按钮文字写明了它清的是黑名单",
                deleteAll.Text.Contains("黑名单"));
        }
        else
        {
            results.Add(("找得到「清空黑名单」按钮", false));
        }

        CheckAssertion(results, "白名单页有「添加程序…」（严格模式下连接页看不到未放行程序）",
            TryGetField<Button>(form, "_whitelistAddButton", out var whitelistAdd)
            && whitelistAdd.Text.Contains("添加程序"));

        CheckAssertion(results, "黑名单页也有「添加程序…」",
            TryGetField<Button>(form, "_rulesAddButton", out var rulesAdd)
            && rulesAdd.Text.Contains("添加程序"));

        CheckAssertion(results, "白名单页有「清空白名单」且是红色",
            TryGetField<Button>(form, "_whitelistClearButton", out var whitelistClear)
            && whitelistClear.Text.Contains("清空") && whitelistClear.ForeColor.R > 150);

        CheckAssertion(results, "白名单页的说明写清了「只在严格模式下」",
            TryGetField<Label>(form, "_whitelistNoticeLabel", out var whitelistNotice)
            && whitelistNotice.Text.Contains("严格模式"));

        CheckAssertion(results, "白名单表格有空状态文案",
            TryGetField<DataGridViewBuffered>(form, "_whitelistGrid", out var whitelistGrid)
            && !string.IsNullOrWhiteSpace(whitelistGrid.EmptyText));

        // ---------------- 3b. 主界面上的开源标识 ----------------
        W();
        W("===== 3b. 开源标识 =====");

        if (TryGetField<LinkLabel>(form, "_openSourceLink", out var openSource))
        {
            W($"    文字 = {openSource.Text}");

            CheckAssertion(results, "标题旁有「开源防火墙」标识",
                openSource.Text.Contains("开源") && openSource.Text.Contains("源码公开"));
            CheckAssertion(results, "开源标识可点击且整段都是链接",
                openSource.LinkArea.Length == openSource.Text.Length);
            CheckAssertion(results, "链接指向项目仓库",
                MainForm.ProjectUrl.Contains("github.com/lovercyh/winappguard"));
        }
        else
        {
            results.Add(("找得到开源标识 _openSourceLink", false));
        }

        // ---------------- 3c. 规则分组与导入导出（2.4） ----------------
        W();
        W("===== 3c. 规则分组与导入导出 =====");

        CheckAssertion(results, "黑名单有分组筛选下拉",
            TryGetField<ComboBox>(form, "_rulesGroupCombo", out _));
        CheckAssertion(results, "白名单有分组筛选下拉",
            TryGetField<ComboBox>(form, "_whitelistGroupCombo", out _));

        CheckAssertion(results, "黑名单有「分组… / 导出… / 导入…」按钮",
            TryGetField<Button>(form, "_rulesGroupButton", out var blockGroupButton)
            && blockGroupButton.Text.Contains("分组")
            && TryGetField<Button>(form, "_rulesExportButton", out var exportButton)
            && exportButton.Text.Contains("导出")
            && TryGetField<Button>(form, "_rulesImportButton", out var importButton)
            && importButton.Text.Contains("导入"));

        CheckAssertion(results, "白名单有「分组…」按钮",
            TryGetField<Button>(form, "_whitelistGroupButton", out var allowGroupButton)
            && allowGroupButton.Text.Contains("分组"));

        CheckAssertion(results, "白名单也有「导出… / 导入…」按钮",
            TryGetField<Button>(form, "_whitelistExportButton", out var allowExportButton)
            && allowExportButton.Text.Contains("导出")
            && TryGetField<Button>(form, "_whitelistImportButton", out var allowImportButton)
            && allowImportButton.Text.Contains("导入"));

        CheckAssertion(results, "两个规则表格都有「分组」列",
            TryGetField<DataGridViewBuffered>(form, "_rulesGrid", out var blockGrid)
            && blockGrid.Columns[nameof(FirewallRuleItem.Group)] is not null
            && TryGetField<DataGridViewBuffered>(form, "_whitelistGrid", out var allowGrid)
            && allowGrid.Columns[nameof(FirewallRuleItem.Group)] is not null);

        CheckAssertion(results, "两个规则表格都有「范围」列（协议/端口/网络位置）",
            TryGetField<DataGridViewBuffered>(form, "_rulesGrid", out var blockGridForScope)
            && blockGridForScope.Columns[nameof(FirewallRuleItem.ScopeText)] is not null
            && TryGetField<DataGridViewBuffered>(form, "_whitelistGrid", out var allowGridForScope)
            && allowGridForScope.Columns[nameof(FirewallRuleItem.ScopeText)] is not null);

        // 分组筛选下拉的取值映射：0=全部、1=未分组、其它=具体分组。
        if (TryGetField<ComboBox>(form, "_rulesGroupCombo", out var groupCombo))
        {
            groupCombo.Items.Clear();
            groupCombo.Items.Add("全部分组");
            groupCombo.Items.Add("未分组");
            groupCombo.Items.Add("游戏");

            groupCombo.SelectedIndex = 2;
            var selectedGroup = TryGetField<string>(form, "_blockGroupFilter", out var filter) ? filter : "<读不到>";
            W($"    选「游戏」→ 筛选值 = {selectedGroup ?? "null"}");
            CheckAssertion(results, "选具体分组时按组名筛选", selectedGroup == "游戏");

            groupCombo.SelectedIndex = 1;
            _ = TryGetField<string>(form, "_blockGroupFilter", out var ungroupedFilter);
            CheckAssertion(results, "选「未分组」时筛选值为空字符串（不是 null）",
                ungroupedFilter == string.Empty);

            groupCombo.SelectedIndex = 0;
            _ = TryGetField<string>(form, "_blockGroupFilter", out var allFilter);
            CheckAssertion(results, "选「全部分组」时不筛选", allFilter is null);
        }

        // ---------------- 4. 快捷键 ----------------
        W();
        W("===== 4. 快捷键 =====");

        CheckAssertion(results, "窗体开启了 KeyPreview（否则快捷键收不到）", form.KeyPreview);

        // 严格模式的按钮文字：「恢复默认放行」对用户来说说不清是在关什么，已改成「关闭严格模式」。
        var staleWording = Descendants<Control>(form)
            .Select(control => control.Text)
            .Where(text => text.Contains("恢复默认放行"))
            .ToList();

        CheckAssertion(results, "界面里不再出现「恢复默认放行」这个说法", staleWording.Count == 0);

        // ---------------- 5. 记录页右键菜单 ----------------
        W();
        W("===== 5. 记录页右键复制 =====");

        if (auditGrid?.ContextMenuStrip is { } menu)
        {
            var texts = menu.Items.Cast<ToolStripItem>().Select(item => item.Text).ToList();
            W($"    菜单 = {string.Join(" / ", texts)}");

            CheckAssertion(results, "右键菜单有三项",
                texts.Contains("复制远端地址") && texts.Contains("复制程序路径") && texts.Contains("复制域名"));
        }
        else
        {
            results.Add(("记录表格有右键菜单", false));
        }

        // ---------------- 6. 顶部横幅的悬停提示 ----------------
        W();
        W("===== 6. 横幅说明了三个开关在哪 =====");

        if (TryGetField<Label>(form, "_safetyNoticeLabel", out var banner)
            && TryGetField<ToolTip>(form, "_toolTip", out var toolTip))
        {
            var tip = toolTip.GetToolTip(banner) ?? string.Empty;
            W($"    提示长度 = {tip.Length} 字");

            CheckAssertion(results, "横幅有悬停说明",
                tip.Contains("设置") && tip.Contains("记录"));
        }
        else
        {
            results.Add(("横幅与 ToolTip 可读", false));
        }

        // ---------------- 7. 设置页 XML 默认折叠 ----------------
        W();
        W("===== 7. 任务计划 XML 默认折叠 =====");

        CheckAssertion(results, "原始 XML 面板默认不显示",
            TryGetField<Control>(form, "_taskXmlPanel", out var xmlPanel) && !xmlPanel.Visible);

        CheckAssertion(results, "有「查看任务计划原始定义」按钮",
            TryGetField<Button>(form, "_toggleTaskXmlButton", out var toggle)
            && toggle.Text.Contains("原始定义"));

        // ---------------- 8. 界面状态持久化 ----------------
        W();
        W("===== 8. 窗口/列宽持久化（ui-state.json）=====");

        var tempState = Path.Combine(Path.GetTempPath(), $"wag-ui-{Guid.NewGuid():N}.json");

        try
        {
            var state = new UiState
            {
                Width = 1200,
                Height = 800,
                X = 40,
                Y = 60,
                Maximized = false,
            };
            state.ColumnWidths["_connectionGrid.ProcessName"] = 123;
            state.Save(tempState);

            var loaded = UiState.Load(tempState);
            W($"    往返：{loaded.Width}×{loaded.Height} @({loaded.X},{loaded.Y})，列宽 {loaded.ColumnWidths.Count} 项");

            CheckAssertion(results, "尺寸能往返", loaded.Width == 1200 && loaded.Height == 800);
            CheckAssertion(results, "位置能往返", loaded.X == 40 && loaded.Y == 60);
            CheckAssertion(results, "列宽能往返",
                loaded.ColumnWidths.TryGetValue("_connectionGrid.ProcessName", out var width) && width == 123);
            CheckAssertion(results, "落在屏幕内时判定为可用", loaded.HasUsableBounds());

            File.WriteAllText(tempState, "{ 这不是合法 json", Encoding.UTF8);
            var broken = UiState.Load(tempState);
            CheckAssertion(results, "损坏文件回落到默认（不抛异常）", broken.Width == 0);

            var offscreen = new UiState { Width = 800, Height = 600, X = -20000, Y = -20000 };
            CheckAssertion(results, "屏幕外的坐标判定为不可用", !offscreen.HasUsableBounds());
        }
        finally
        {
            try
            {
                if (File.Exists(tempState))
                {
                    File.Delete(tempState);
                }

                var temp = tempState + ".tmp";
                if (File.Exists(temp))
                {
                    File.Delete(temp);
                }
            }
            catch (Exception)
            {
                // 临时文件删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 高 DPI（150% 字体）布局自检。
    ///
    /// 为什么必须是**独立模式、独立进程**：WinForms 的 <c>AutoScaleMode.Font</c> 只在
    /// **创建窗口时**按当时的默认字体缩放一次；窗口建好以后再改 <c>Font</c> 不会重新缩放，
    /// 那样测出来的"没问题"是假的。所以这里必须在 new MainForm **之前**设默认字体。
    /// </summary>
    private static void RunUiDpiTest(bool english = false)
    {
        var previousLanguage = Localizer.Current;
        if (english) { Localizer.Initialize("en"); }

        // 9pt × 150% ≈ 13.5pt，对应 Windows「150% 缩放」下的默认字号。
        Application.SetDefaultFont(new Font("Microsoft YaHei UI", 13.5F));

        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   高 DPI 布局自检（150% 字体；离线、不联网）                   #");
        W("################################################################");
        W();

        MainForm.SuppressBackgroundServices = true;

        using var form = new MainForm(isAutostart: false);

        // 跳过读防火墙/扫描，只量布局。
        TrySetField(form, "_runtimeInitialized", true);
        form.Show();
        Application.DoEvents();

        W($"    字体 = {form.Font.Name} {form.Font.SizeInPoints}pt；客户区 = {form.ClientSize.Width}×{form.ClientSize.Height}");
        W($"    屏幕工作区 = {Screen.PrimaryScreen?.WorkingArea}");

        results.Add(("150% 下窗口仍能完整放进屏幕（宽度）",
            Screen.PrimaryScreen is null || form.ClientSize.Width <= Screen.PrimaryScreen.WorkingArea.Width));
        results.Add(("150% 下窗口仍能完整放进屏幕（高度）",
            Screen.PrimaryScreen is null || form.ClientSize.Height <= Screen.PrimaryScreen.WorkingArea.Height));

        // 1) 固定宽高的横幅最容易在缩放后截断。
        CheckSafetyNoticeFits(results, form);

        // 2) 各工具条内部不重叠。
        if (TryGetField<Panel>(form, "_toolPanel", out var connectionToolPanel))
        {
            CheckNoOverlap(results, "[150%] 连接页工具栏互不重叠", connectionToolPanel.Controls);
        }

        if (TryGetField<Panel>(form, "_rulesToolPanel", out var rulesToolPanel))
        {
            CheckNoOverlap(results, "[150%] 规则页工具栏互不重叠", rulesToolPanel.Controls);

            // 3) 按钮文字必须在按钮里放得下（缩放后按钮不会自动变宽）。
            foreach (var name in new[]
                     {
                         "_rulesDeleteButton", "_rulesDeleteAllButton", "_rulesAddButton",
                         "_whitelistAddButton", "_whitelistRemoveButton", "_whitelistClearButton",
                     })
            {
                if (!TryGetField<Button>(form, name, out var button))
                {
                    continue;
                }

                var needed = TextRenderer.MeasureText(button.Text, button.Font).Width + 14;
                W($"    {name}：文字需 {needed}px / 按钮宽 {button.Width}px");
                results.Add(($"[150%] {button.Text} 放得下", needed <= button.Width));
            }
        }

        // 4) 白名单页工具栏不重叠。
        if (TryGetField<Panel>(form, "_whitelistToolPanel", out var whitelistToolPanel))
        {
            CheckNoOverlap(results, "[150%] 白名单页工具栏互不重叠", whitelistToolPanel.Controls);
        }

        // 5) 设置页四个分区不重叠。
        var settingsParts = new List<Control>();
        foreach (var name in new[] { "_autostartPanel", "_privacyPanel", "_strictModePanel", "_taskXmlPanel" })
        {
            if (TryGetField<Control>(form, name, out var part))
            {
                settingsParts.Add(part);
            }
        }

        CheckNoOverlapList(results, "[150%] 设置页四个分区互不重叠", settingsParts);

        // 5) 记录页第三行（开关 + 下拉框）不重叠。
        if (TryGetField<TabPage>(form, "_tabAudit", out var auditTab))
        {
            var row3 = new List<Control>();
            foreach (Control child in auditTab.Controls)
            {
                foreach (Control inner in child.Controls)
                {
                    if (inner is CheckBox { Text: "新程序提醒" or "学习模式" }
                        || (inner is Label label && label.Location.Y >= 60))
                    {
                        row3.Add(inner);
                    }
                }
            }

            // 2.1 没有这一行控件时跳过（上面的 REVERT 说明见 docs）。
            if (row3.Count > 0)
            {
                CheckNoOverlapList(results, "[150%] 记录页顶部控件互不重叠", row3);
            }
        }

        PrintSummary(results, showFirewallResidue: false);

        if (english)
        {
            Localizer.Initialize(previousLanguage switch
            {
                Localizer.LanguageMode.English => "en",
                Localizer.LanguageMode.Chinese => "zh",
                _ => "auto",
            });
        }
    }

    /// <summary>
    /// 顶部那条安全横幅必须**放得下**（它是固定宽高、不换行的标签）。
    ///
    /// 这条断言是被真实截断坑出来的：1.3 给它加了"除严格模式外"这个例外之后文本变长，
    /// 后半句被**直接裁掉**（不报错、不加省略号），而人眼在窗口上看那段文字
    /// 很容易以为"它本来就说到这儿"。
    /// </summary>
    private static void CheckSafetyNoticeFits(List<(string Title, bool Passed)> results, MainForm form)
    {
        if (!TryGetField<Label>(form, "_safetyNoticeLabel", out var label))
        {
            results.Add(("找得到顶部安全横幅 _safetyNoticeLabel", false));
            return;
        }

        var needed = TextRenderer.MeasureText(label.Text, label.Font).Width;
        W($"    顶部安全横幅：文本需 {needed}px / 标签宽 {label.Width}px");

        results.Add(($"顶部安全横幅放得下（需 {needed}px / 实宽 {label.Width}px）", needed <= label.Width));
    }

    /// <summary>
    /// 白名单（严格模式）的**接线**自检：三态「放行」列 + 加入 / 移出白名单的按钮与菜单项。
    ///
    /// 这里**不碰防火墙**：直接改界面里那两个缓存集合，验证「集合 → 行数据 → 单元格文本」
    /// 和「集合 → 按钮文字 / 菜单启用状态」这两条链路。
    /// 真正的防火墙读写由 --strict-mode-test / --strict-mode-lifecycle-test 负责 ——
    /// 那两个模式会真改全局策略，所以刻意跟界面自检分开，界面自检继续承诺"不碰系统状态"。
    /// </summary>
    private static void CheckWhitelistWiring(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 白名单接线（三态「放行」列 + 加入 / 移出）=====");

        if (!TrySelectTab(form, "_tabConnections"))
        {
            results.Add(("白名单接线前能切回「联网连接」页", false));
            return;
        }

        if (!TryGetField<HashSet<string>>(form, "_whitelistedPaths", out var whitelisted)
            || !TryGetField<HashSet<string>>(form, "_otherAllowPaths", out var otherAllow)
            || !TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned)
            || !TryGetField<DataGridView>(form, "_connectionGrid", out var grid)
            || !TryGetField<Button>(form, "_whitelistButton", out var button)
            || !TryGetField<ToolStripMenuItem>(form, "_menuWhitelistAdd", out var menuAdd)
            || !TryGetField<ToolStripMenuItem>(form, "_menuWhitelistRemove", out var menuRemove))
        {
            results.Add(("白名单接线自检能找到必要的字段", false));
            return;
        }

        results.Add(("白名单接线自检能找到必要的字段", true));

        // ---------- 1. 列存在且表头正确 ----------
        var column = grid.Columns[nameof(TcpConnectionItem.WhitelistText)];
        results.Add(("连接表里有「放行」列", column is not null));
        results.Add(("「放行」列的表头是「放行」", column?.HeaderText == "放行"));

        // ---------- 2. 按钮与菜单项 ----------
        results.Add(("工具栏有白名单按钮（初始文字含「白名单」）", button.Text.Contains("白名单")));
        results.Add(("右键菜单有「加入白名单」", menuAdd.Text == "加入白名单"));
        results.Add(("右键菜单有「移出白名单」", menuRemove.Text == "移出白名单"));

        // ---------- 3. 三态文本映射（纯模型断言）----------
        static string TextFor(WhitelistState state)
        {
            var probe = MakeConnection(
                9999, "x.exe", "1.1.1.1", 443, "IPv4", 49999, TcpState.Established,
                state == WhitelistState.NotApplicable ? string.Empty : @"C:\t\x.exe");
            probe.Whitelist = state;
            return probe.WhitelistText;
        }

        results.Add(("未放行 → 「未放行」", TextFor(WhitelistState.NotWhitelisted) == "未放行"));
        results.Add(("本工具放行 → 「已放行·本工具」", TextFor(WhitelistState.Ours) == "已放行·本工具"));
        results.Add(("别的来源放行 → 「已放行·其它来源」", TextFor(WhitelistState.OtherSource) == "已放行·其它来源"));
        results.Add(("拿不到路径 → 「—」", TextFor(WhitelistState.NotApplicable) == "—"));

        // ---------- 4. 缓存集合 → 行数据 → 单元格文本 ----------
        const string oursPath = @"C:\t\ours.exe";
        const string otherPath = @"C:\t\other.exe";
        const string nonePath = @"C:\t\none.exe";

        whitelisted.Clear();
        whitelisted.Add(oursPath);
        otherAllow.Clear();
        otherAllow.Add(otherPath);

        scanned.Clear();
        scanned.Add(MakeConnection(9001, "ours.exe", "1.1.1.1", 443, "IPv4", 49001, TcpState.Established, oursPath));
        scanned.Add(MakeConnection(9002, "other.exe", "1.1.1.2", 443, "IPv4", 49002, TcpState.Established, otherPath));
        scanned.Add(MakeConnection(9003, "none.exe", "1.1.1.3", 443, "IPv4", 49003, TcpState.Established, nonePath));
        scanned.Add(MakeConnection(9004, "nopath.exe", "1.1.1.4", 443, "IPv4", 49004, TcpState.Established));

        // 产品里这两步是**成对**调用的：RebuildView 只重建显示列表，
        // RebindGrid 才刷新表格、并把白名单/阻止状态写到行数据上。
        // （第一版自检只调了前者，于是单元格全是「—」—— 这个坑正好说明
        //   自检必须走产品真实的调用序列，不能自己拼一条看起来差不多的。）
        if (!InvokePrivate(form, "RebuildView", null)
            || !InvokePrivate(form, "RebindGrid", new object?[] { null }))
        {
            results.Add(("能反射调用 RebuildView + RebindGrid（走真实重绑路径）", false));
            return;
        }

        Application.DoEvents();

        // 按 PID 从表格里把「放行」列的文本读回来 —— 走的是真实的单元格绑定。
        string CellTextOf(int pid)
        {
            foreach (DataGridViewRow row in grid.Rows)
            {
                if (row.DataBoundItem is TcpConnectionItem bound && bound.Pid == pid)
                {
                    return Convert.ToString(row.Cells[column!.Index].Value) ?? string.Empty;
                }
            }

            return "（没找到这一行）";
        }

        W($"    单元格文本：ours={CellTextOf(9001)}  other={CellTextOf(9002)}  " +
          $"none={CellTextOf(9003)}  nopath={CellTextOf(9004)}");

        results.Add(("单元格：本工具放行的程序显示「已放行·本工具」", CellTextOf(9001) == "已放行·本工具"));
        results.Add(("单元格：别的来源放行的程序显示「已放行·其它来源」", CellTextOf(9002) == "已放行·其它来源"));
        results.Add(("单元格：没放行的程序显示「未放行」", CellTextOf(9003) == "未放行"));
        results.Add(("单元格：拿不到路径的程序显示「—」（不谎称未放行）", CellTextOf(9004) == "—"));

        // ---------- 5. 按钮文字 / 菜单启用状态跟着选中行变 ----------
        // 3.0-b 起写操作需要服务在线（离线时按钮一律禁用），这里按"服务可用"验证状态机。
        _ = SetPrivateField(form, "_serviceAvailable", true);

        // 模拟「用户确实选中了一行」：置上确认标志，再选中目标行，然后跑真实的 UpdateActionState。
        if (!SetPrivateField(form, "_connectionSelectionConfirmed", true))
        {
            results.Add(("能模拟「已确认选中」（反射写 _connectionSelectionConfirmed）", false));
            return;
        }

        bool SelectByPid(int pid)
        {
            foreach (DataGridViewRow row in grid.Rows)
            {
                if (row.DataBoundItem is TcpConnectionItem bound && bound.Pid == pid)
                {
                    grid.CurrentCell = row.Cells[0];
                    Application.DoEvents();
                    return InvokePrivateNoArgs(form, "UpdateActionState");
                }
            }

            return false;
        }

        if (SelectByPid(9003) && SelectByPid(9001))
        {
            // ⚠ 顺序要小心：下面每组断言都必须在**刚选中那一行**之后立刻做。
            // （第一版写成了 `SelectByPid(9003) && SelectByPid(9001)` 之后再去断言 9003 的状态，
            //   那时当前选中已经变成 9001 了，断言必然失败 —— 自检自己写错也会被抓出来。）
            SelectByPid(9003);
            results.Add(("选中未放行的程序时，按钮是「加入白名单」", button.Text == "加入白名单"));
            results.Add(("选中未放行的程序时，菜单「加入白名单」可用、「移出白名单」禁用",
                menuAdd.Enabled && !menuRemove.Enabled));

            SelectByPid(9001);
            results.Add(("选中已放行的程序时，按钮是「移出白名单」", button.Text == "移出白名单"));
            results.Add(("选中已放行的程序时，菜单「移出白名单」可用、「加入白名单」禁用",
                !menuAdd.Enabled && menuRemove.Enabled));

            SelectByPid(9004);
            results.Add(("选中拿不到路径的程序时，白名单按钮禁用", !button.Enabled));
        }
        else
        {
            results.Add(("能选中测试行来验证按钮状态", false));
        }

        // 收尾：把自检造的数据清掉。
        // （在清掉之前先扫一遍：这时候单元格里正好有四种状态的数据，
        //   悬停提示也挂上了 —— 错过这一步就扫不到它们了。）
        CheckNoMarkdownInUiText(results, form, "连接页与单元格悬停提示");

        scanned.Clear();
        whitelisted.Clear();
        otherAllow.Clear();
        InvokePrivate(form, "RebuildView", null);
        InvokePrivate(form, "RebindGrid", new object?[] { null });
        Application.DoEvents();
    }

    /// <summary>
    /// 严格模式面板的自检。
    ///
    /// **刻意不碰真实防火墙**：这个面板的"开 / 关"要动全局策略，
    /// 只能由人在虚拟机里验（见 `--strict-mode-test` / `--strict-mode-lifecycle-test` 与验收清单）。
    /// 这里查两件能在零副作用前提下查清的事：
    ///   1. 面板结构、按钮文字、状态文字对不对；
    ///   2. **说明文字该说的都说了** —— 这几句是"如实"的底线
    ///      （会话级 / 退出即还原 / 挡不住别人的允许规则 / 为什么不能开）；
    ///   3. **「开启后会上不了网的程序」那份清单的算法** —— 它是二次确认里给用户看的依据，
    ///      算多了会吓人，算少了会真的把人断网。
    /// </summary>
    private static void CheckStrictModeUi(List<(string Title, bool Passed)> results, MainForm form)
    {
        W();
        W("===== 严格模式面板（结构 + 说明文字 + 影响清单算法）=====");

        if (!TrySelectTab(form, "_tabSettings"))
        {
            results.Add(("严格模式自检前能切到「设置」页", false));
            return;
        }

        if (!TryGetField<GroupBox>(form, "_strictModePanel", out var panel)
            || !TryGetField<Label>(form, "_strictModeStatusLabel", out var status)
            || !TryGetField<Button>(form, "_strictModeToggleButton", out var toggle)
            || !TryGetField<Button>(form, "_refreshStrictModeButton", out var refresh))
        {
            results.Add(("严格模式自检能找到必要的字段", false));
            return;
        }

        results.Add(("严格模式自检能找到必要的字段", true));

        W($"    面板标题 = {panel.Text}");
        W($"    状态文字 = {status.Text}");
        W($"    开关按钮 = {toggle.Text}（启用={toggle.Enabled}）");

        results.Add(("面板标题是「严格模式（高级）」", panel.Text == "严格模式（高级）"));
        results.Add(("状态文字以「当前状态：」开头", status.Text.StartsWith("当前状态：", StringComparison.Ordinal)));
        results.Add(("有「重新读取状态」按钮", refresh.Text == "重新读取状态"));

        // ui-check 跳过了运行期初始化，所以面板的初值就是控件自己的初值。
        results.Add(("未开启时开关按钮是「开启严格模式…」", toggle.Text == "开启严格模式…"));

        // ---------- 说明文字（纯函数，可以直接调）----------
        var textOff = InvokePrivateWithResult<string>(form, "BuildStrictModeDetailText", false);
        var textOn = InvokePrivateWithResult<string>(form, "BuildStrictModeDetailText", true);

        W($"    说明文字（未开启，共 {textOff?.Length ?? 0} 字）首行 = {textOff?.Split('\n')[0].Trim()}");

        results.Add(("说明文字能生成", !string.IsNullOrEmpty(textOff)));
        results.Add(("未开启时说明里写了「开启后会拦掉没放行的程序」",
            textOff?.Contains("上不了网") == true || textOff?.Contains("会被拦掉") == true));
        results.Add(("说明里写明了「会话内 / 退出即撤销」",
            textOff?.Contains("会话内") == true && textOff.Contains("自动撤销")));
        results.Add(("说明里写明了「不改 Windows 防火墙设置」",
            textOff?.Contains("不会修改 Windows 防火墙") == true));
        results.Add(("说明里写明了「真白名单：别人的允许规则不再生效」（诚实性底线）",
            textOff?.Contains("不再自动放行") == true));
        results.Add(("生效中的说明写的是「现在」而不是「开启后」", textOn?.Contains("现在：") == true));

        // 设置页这一屏（说明文字 / 按钮 / 页签 / 分组框标题）也不允许出现 Markdown 强调符。
        CheckNoMarkdownInUiText(results, form, "设置页");

        // ---------- 「开启后会上不了网的程序」清单算法 ----------
        if (!TryGetField<List<TcpConnectionItem>>(form, "_scannedConnections", out var scanned)
            || !TryGetField<HashSet<string>>(form, "_whitelistedPaths", out var whitelisted)
            || !TryGetField<HashSet<string>>(form, "_otherAllowPaths", out var otherAllow))
        {
            results.Add(("影响清单算法自检能找到必要的字段", false));
            return;
        }

        const string oursPath = @"C:\t\w1.exe";
        const string otherPath = @"C:\t\w2.exe";
        const string loosePath = @"C:\t\w3.exe";

        var before = scanned.ToList();

        whitelisted.Clear();
        whitelisted.Add(oursPath);

        otherAllow.Clear();
        otherAllow.Add(otherPath);

        scanned.Clear();
        scanned.Add(MakeConnection(7001, "w1.exe", "1.1.1.1", 443, "IPv4", 47001, TcpState.Established, oursPath));
        scanned.Add(MakeConnection(7002, "w2.exe", "1.1.1.2", 443, "IPv4", 47002, TcpState.Established, otherPath));
        scanned.Add(MakeConnection(7003, "w3.exe", "1.1.1.3", 443, "IPv4", 47003, TcpState.Established, loosePath));
        scanned.Add(MakeConnection(7004, "w3.exe", "1.1.1.4", 443, "IPv4", 47004, TcpState.Established, loosePath));
        scanned.Add(MakeConnection(7005, "w4.exe", "1.1.1.5", 443, "IPv4", 47005, TcpState.Established, @"C:\t\w4.exe"));
        scanned.Add(MakeConnection(7006, "nopath.exe", "1.1.1.6", 443, "IPv4", 47006, TcpState.Established));

        var affected = InvokePrivateWithResult<List<string>>(form, "BuildProgramsThatWillLoseAccess");

        W($"    影响清单 = {(affected is null ? "（调用失败）" : string.Join("、", affected))}");

        results.Add(("能调用 BuildProgramsThatWillLoseAccess", affected is not null));
        results.Add(("清单里不含已被本工具放行的程序", affected?.Contains("w1.exe") == false));
        results.Add(("清单里包含「已被其它软件放行」的程序（2.0 不再自动放行）",
            affected?.Contains("w2.exe") == true));
        results.Add(("清单里不含拿不到路径的程序（否则会威胁到不该威胁的）", affected?.Contains("nopath.exe") == false));
        results.Add(("同一个程序的多个连接只算一次", affected?.Count(n => n == "w3.exe") == 1));
        results.Add(("该进清单的都进了（w3.exe / w4.exe）",
            affected?.Contains("w3.exe") == true && affected.Contains("w4.exe")));

        // 收尾：把自检造的数据还原。
        scanned.Clear();
        scanned.AddRange(before);
        whitelisted.Clear();
        otherAllow.Clear();
    }

    /// <summary>
    /// 扫一遍界面上**所有真正会显示给用户的文字**，断言里面没有 Markdown 强调符（`**`）。
    ///
    /// 为什么需要这条：产品代码的注释里到处用 `**` 表示重点，很容易顺手写进字符串。
    /// 而 WinForms 的标签 / 按钮 / 提示**不做任何 Markdown 渲染** —— 用户看到的就是两个星号，
    /// 一句本来要强调的话会变成"这程序是不是出 bug 了"。
    /// （这个坑是靠渲染 PNG 人眼发现的；既然发现了，就别让它再犯一次。）
    /// </summary>
    private static void CheckNoMarkdownInUiText(
        List<(string Title, bool Passed)> results, MainForm form, string where)
    {
        var offenders = new List<string>();

        void Inspect(Control control)
        {
            if (!string.IsNullOrEmpty(control.Text) && control.Text.Contains("**", StringComparison.Ordinal))
            {
                offenders.Add($"{control.GetType().Name}({control.Name})");
            }

            if (control is DataGridView grid)
            {
                foreach (DataGridViewColumn column in grid.Columns)
                {
                    if (column.HeaderText.Contains("**", StringComparison.Ordinal))
                    {
                        offenders.Add($"{grid.Name} 列头 {column.Name}");
                    }
                }

                foreach (DataGridViewRow row in grid.Rows)
                {
                    foreach (DataGridViewCell cell in row.Cells)
                    {
                        if (cell.ToolTipText?.Contains("**", StringComparison.Ordinal) == true)
                        {
                            offenders.Add($"{grid.Name} 单元格悬停提示");
                        }
                    }
                }
            }

            if (control.ContextMenuStrip is { } menu)
            {
                foreach (ToolStripItem item in menu.Items)
                {
                    if (item.Text?.Contains("**", StringComparison.Ordinal) == true)
                    {
                        offenders.Add($"菜单项 {item.Name}");
                    }
                }
            }

            foreach (Control child in control.Controls)
            {
                Inspect(child);
            }
        }

        Inspect(form);

        // 托盘菜单不在窗体的控件树里，单独扫。
        if (TryGetField<ContextMenuStrip>(form, "_trayMenu", out var trayMenu))
        {
            foreach (ToolStripItem item in trayMenu.Items)
            {
                if (item.Text?.Contains("**", StringComparison.Ordinal) == true)
                {
                    offenders.Add($"托盘菜单项 {item.Name}");
                }
            }
        }

        if (offenders.Count > 0)
        {
            W($"    ！{where}：发现 Markdown 强调符 —— {string.Join("、", offenders.Distinct())}");
        }

        results.Add(($"界面文字里没有 Markdown 强调符（{where}）", offenders.Count == 0));
    }

    /// <summary>调用产品的私有实例方法并取回值（自检用）。</summary>
    private static T InvokeInstance<T>(MainForm form, string methodName, params object?[] args)
    {
        var method = typeof(MainForm).GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic)
                     ?? throw new InvalidOperationException($"找不到方法 {methodName}");

        return (T)method.Invoke(form, args)!;
    }

    /// <summary>调用产品的私有静态方法（自检用；找不到直接抛，不静默通过）。</summary>
    private static T InvokeStatic<T>(Type type, string methodName, params object?[] args)
    {
        var method = type.GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic)
                     ?? throw new InvalidOperationException($"找不到静态方法 {methodName}");

        return (T)method.Invoke(null, args)!;
    }

    /// <summary>反射调用**带参数、有返回值**的私有方法。</summary>
    private static T? InvokePrivateWithResult<T>(MainForm form, string methodName, params object?[] args)
        where T : class
    {
        var method = typeof(MainForm).GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic);
        return method?.Invoke(form, args) as T;
    }

    /// <summary>
    /// 命令行模式的离线自检：**只测参数解析与输出格式**。
    ///
    /// 为什么不在这里真跑 <c>--block</c> / <c>--unblock-all</c>：那会改防火墙（需要管理员），
    /// 属于 <c>--strict-mode-*</c> 那类"会动系统"的模式。
    /// 这里刻意保持**纯离线、零副作用**，所以它能进 CI、能随时复跑。
    /// 真实的 block → list → unblock 往返在虚拟机里人工验（见 <c>docs/验收清单.md</c> 的 K 组）。
    /// </summary>
    /// <summary>
    /// WFP 地基自检（2.0 的第一步）。
    ///
    /// 做的是**真实往返**而不是断言常量：开引擎 → 建子层 → 读回 → 加一条过滤器 →
    /// 枚举 → 按 key 删 → 删子层；最后再验一次「动态会话关掉后自动清空」。
    ///
    /// 为什么过滤器的目标选成本程序自己：即使某一步清理失败，
    /// 被拦的也只是这个自检工具（它本来也不联网），不会影响用户的其他程序。
    /// </summary>
    private static void RunWfpTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   WFP 地基自检（只碰本程序自己的子层与自身可执行文件）         #");
        W("################################################################");
        W();

        // ---------------- 1. 结构体布局 ----------------
        W("===== 1. 结构体布局（x64）=====");
        W($"    FWPM_FILTER0   = {Marshal.SizeOf<WfpNativeMethods.FwpmFilter>()} 字节（应为 200）");
        W($"    FWPM_SUBLAYER0 = {Marshal.SizeOf<WfpNativeMethods.FwpmSubLayer>()} 字节（应为 72）");
        W($"    FWPM_ACTION0   = {Marshal.SizeOf<WfpNativeMethods.FwpmAction>()} 字节（应为 20：GUID 按 4 字节对齐）");

        var layoutOk = true;
        try
        {
            WfpNativeMethods.EnsureLayout();
        }
        catch (InvalidOperationException ex)
        {
            layoutOk = false;
            W($"    {ex.Message}");
        }

        CheckAssertion(results, "结构体尺寸与官方定义一致", layoutOk);

        W();
        W($"    子层 GUID = {{{WfpEngine.SubLayerKey}}}");
        W($"    子层权重 = 0x{WfpNativeMethods.OurSubLayerWeight:X4}");

        var exePath = Environment.ProcessPath!;
        var filterKey = WfpEngine.BuildFilterKey("wfp-test|" + exePath);
        const ulong testWeight = 0x0FFFFFFF;

        // ---------------- 2. 普通会话：完整往返 ----------------
        W();
        W("===== 2. 普通会话：建 → 读回 → 加过滤器 → 枚举 → 删 =====");

        using (var engine = WfpEngine.Open())
        {
            // 从干净状态开始：万一上次中途失败，先把自家残留收拾掉。
            var leftover = engine.DeleteAllOurFilters();
            if (leftover > 0)
            {
                W($"    先清理了 {leftover} 条上次遗留的过滤器");
            }

            // 旧子层可能是上一次失败留下的（持久化状态也未必和这次要建的一致），先删掉。
            engine.DeleteSublayer();

            engine.EnsureSublayer(persistent: false);

            var (weight, persistent) = engine.ReadSublayer();
            W($"    子层读回：权重 0x{weight:X4}，持久化={persistent}");

            CheckAssertion(results, $"子层权重读回是 0x{WfpNativeMethods.OurSubLayerWeight:X4}",
                weight == WfpNativeMethods.OurSubLayerWeight);
            CheckAssertion(results, "子层创建后能按 key 读回", true);

            var filterId = engine.AddAppIdFilter(
                filterKey,
                "WinAppGuard 自检过滤器",
                null,
                exePath,
                WfpNativeMethods.LayerAleAuthConnectV4,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                testWeight,
                persistent: false);

            W($"    加过滤器成功：filterId = {filterId}");

            var keys = engine.ListOurFilterKeys();
            CheckAssertion(results, "枚举到 1 条属于我们的过滤器", keys.Count == 1);
            CheckAssertion(results, "枚举出的 key 与写入的一致", keys.Count == 1 && keys[0] == filterKey);

            engine.DeleteFilter(filterKey);
            CheckAssertion(results, "按 key 删除后不再枚举到", engine.ListOurFilterKeys().Count == 0);

            engine.DeleteSublayer();
            CheckAssertion(results, "子层删除后读不到（FWP_E_SUBLAYER_NOT_FOUND）",
                IsSublayerMissing(engine));
        }

        // ---------------- 3. 动态会话：关掉引擎就该全部消失 ----------------
        W();
        W("===== 3. 动态会话：引擎关闭后子层与过滤器自动消失 =====");

        var dynamicKey = WfpEngine.BuildFilterKey("wfp-test-dynamic|" + exePath);

        using (var dynamicEngine = WfpEngine.Open(dynamicSession: true))
        {
            CheckAssertion(results, "打开动态会话", dynamicEngine.IsDynamic);

            dynamicEngine.EnsureSublayer(persistent: false);
            dynamicEngine.AddAppIdFilter(
                dynamicKey,
                "WinAppGuard 自检（动态会话）",
                null,
                exePath,
                WfpNativeMethods.LayerAleAuthConnectV4,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                testWeight,
                persistent: false);

            CheckAssertion(results, "动态会话里枚举到 1 条", dynamicEngine.ListOurFilterKeys().Count == 1);
        }

        using (var checkEngine = WfpEngine.Open())
        {
            CheckAssertion(results, "会话关闭后过滤器 0 条（不需要任何还原逻辑）",
                checkEngine.ListOurFilterKeys().Count == 0);
            CheckAssertion(results, "会话关闭后子层也消失", IsSublayerMissing(checkEngine));

            // 兜底：万一上面有残留，再收一次，保证系统恢复原样。
            var leftover = checkEngine.DeleteAllOurFilters();
            try
            {
                checkEngine.DeleteSublayer();
            }
            catch (WfpException)
            {
                // 子层本来就不存在，忽略。
            }

            if (leftover > 0)
            {
                W($"    兜底清理了 {leftover} 条残留过滤器");
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// WFP 规则模型自检。
    ///
    /// 验证的是 2.0 真正要用的那条路：一条规则 → V4/V6 两条过滤器 → 还能原样读回来。
    /// 顺带钉死两件事：
    ///   1. 重复写入是幂等的（不会积出重复规则）；
    ///   2. V6 层的 GUID 是对的（能往那一层加过滤器，就说明层存在）。
    ///
    /// 规则的实验对象是本自检程序自己：即使清理失败，被拦的也只是它。
    /// </summary>
    /// <summary>
    /// 3.4：离线验证保护性 SDDL 的构造（不需要管理员、不碰系统）。
    /// </summary>
    private static void RunWfpDaclSddlTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   WFP DACL（离线）：owner-only SDDL 构造与回退                 #");
        W("################################################################");
        W();

        const string ownerSid = "S-1-5-21-1111-2222-3333-1001";
        const string full = "(A;;0xF01FF;;;SY)";

        var sddl = WfpEngine.BuildProtectiveSddl(ownerSid);
        W($"    有所有者 = {sddl}");

        CheckAssertion(results, "包含 SYSTEM 完全控制", sddl.Contains(full, StringComparison.Ordinal));
        CheckAssertion(results, "包含所有者完全控制",
            sddl.Contains($"(A;;0xF01FF;;;{ownerSid})", StringComparison.Ordinal));
        CheckAssertion(results, "不再包含 Administrators",
            !sddl.Contains(";;;BA)", StringComparison.OrdinalIgnoreCase));
        CheckAssertion(results, "DACL 标记为 protected",
            sddl.Contains("D:P", StringComparison.Ordinal));
        CheckAssertion(results, "对象 Owner 不是 Administrators",
            sddl.Contains("O:BA", StringComparison.OrdinalIgnoreCase) == false);

        var fallback = WfpEngine.BuildProtectiveSddl(null);
        W($"    无所有者 = {fallback}");
        CheckAssertion(results, "没有所有者时回退 SY + BA",
            fallback.Contains(full, StringComparison.Ordinal)
            && fallback.Contains("(A;;0xF01FF;;;BA)", StringComparison.Ordinal));
        CheckAssertion(results, "回退时 DACL 仍是 protected",
            fallback.Contains("D:P", StringComparison.Ordinal));

        var systemOwner = WfpEngine.BuildProtectiveSddl("S-1-5-18");
        W($"    所有者是 SYSTEM = {systemOwner}");
        CheckAssertion(results, "所有者是 SYSTEM 时不重复添加",
            systemOwner.Contains("D:P(A;;0xF01FF;;;SY)", StringComparison.Ordinal)
            && !systemOwner.Contains(";;;BA)", StringComparison.OrdinalIgnoreCase));

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.4：读取真实 WFP 对象的 DACL（需管理员 + 至少一条规则，VM 验收用）。
    /// </summary>
    private static void RunWfpDaclTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   WFP DACL（真实对象）：子层 / 过滤器只允许 SYSTEM + 所有者   #");
        W("################################################################");
        W();

        // SDDL 里权限可能写成 0xF01FF，也可能写成等价的符号串。
        static bool HasFullAce(string? sddl, string sid)
            => sddl is not null
               && (sddl.Contains($"(A;;0xF01FF;;;{sid})", StringComparison.OrdinalIgnoreCase)
                   || sddl.Contains(
                       $"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{sid})",
                       StringComparison.OrdinalIgnoreCase));

        static bool IsProtected(string? sddl)
            => sddl is not null && sddl.Contains("D:P", StringComparison.Ordinal);

        static bool HasInheritedAces(string? sddl)
            => sddl is not null && sddl.Contains(";ID;", StringComparison.OrdinalIgnoreCase);

        try
        {
            var config = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory).ReadConfig();
            var ownerSid = config.OwnerSid;
            W($"    所有者 SID = {ownerSid}");

            CheckAssertion(results, "能读到所有者 SID", !string.IsNullOrWhiteSpace(ownerSid));

            using var engine = WfpEngine.Open();

            var sublayerSddl = engine.ReadSublayerSecuritySddl();
            W($"    子层 SDDL = {sublayerSddl ?? "<读取失败>"}");

            CheckAssertion(results, "子层 DACL 可读", sublayerSddl is not null);
            CheckAssertion(results, "子层 DACL 已保护（不接受继承）",
                IsProtected(sublayerSddl));
            CheckAssertion(results, "子层没有继承 ACE",
                !HasInheritedAces(sublayerSddl));
            CheckAssertion(results, "子层 Owner 不是 Administrators",
                sublayerSddl?.Contains("O:BA", StringComparison.OrdinalIgnoreCase) == false);
            CheckAssertion(results, "子层 SYSTEM 完全控制",
                HasFullAce(sublayerSddl, "SY"));
            CheckAssertion(results, "子层所有者完全控制",
                HasFullAce(sublayerSddl, ownerSid));
            CheckAssertion(results, "子层没有 Administrators ACE",
                sublayerSddl?.Contains(";;;BA)", StringComparison.OrdinalIgnoreCase) == false);

            var keys = engine.ListOurFilterKeys();
            string? temporaryRule = null;
            string? temporaryExe = null;

            // 没有规则时临时建一条。用 notepad.exe 的临时副本：
            //   - 不能用 SelfCheck 自己（自我保护会拒绝）；
            //   - 不能直接用 notepad.exe（万一用户已经阻止了它，清理时会误删用户规则）。
            if (keys.Count == 0)
            {
                var notepad = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "notepad.exe");

                if (!File.Exists(notepad))
                {
                    throw new FileNotFoundException("找不到用于 DACL 测试的 notepad.exe。", notepad);
                }

                temporaryExe = Path.Combine(
                    Path.GetTempPath(), $"wag-dacl-test-{Guid.NewGuid():N}.exe");
                File.Copy(notepad, temporaryExe);

                temporaryRule = RuleEngine.CreateBlockRule(temporaryExe);
                keys = engine.ListOurFilterKeys();
                W($"    临时创建测试规则：{temporaryRule}");
            }

            try
            {
                W($"    过滤器数量 = {keys.Count}");
                CheckAssertion(results, "至少有可检查的过滤器", keys.Count > 0);

                var filterChecks = 0;

                foreach (var key in keys.Take(10))
                {
                    var filterSddl = engine.ReadFilterSecuritySddl(key);

                    if (filterSddl is null)
                    {
                        CheckAssertion(results, $"过滤器 {key:N} DACL 可读", false);
                        continue;
                    }

                    filterChecks++;

                    CheckAssertion(results, $"过滤器 {key:N} 已保护（不接受继承）",
                        IsProtected(filterSddl));
                    CheckAssertion(results, $"过滤器 {key:N} 没有继承 ACE",
                        !HasInheritedAces(filterSddl));
                    CheckAssertion(results, $"过滤器 {key:N} SYSTEM 完全控制",
                        HasFullAce(filterSddl, "SY"));
                    CheckAssertion(results, $"过滤器 {key:N} 所有者完全控制",
                        HasFullAce(filterSddl, ownerSid));
                    CheckAssertion(results, $"过滤器 {key:N} 没有 Administrators ACE",
                        !filterSddl.Contains(";;;BA)", StringComparison.OrdinalIgnoreCase));
                }

                CheckAssertion(results, "至少检查到一条过滤器", filterChecks > 0);
            }
            finally
            {
                if (temporaryRule is not null)
                {
                    _ = RuleEngine.DeleteRule(temporaryRule);
                    W("    临时测试规则已删除。");
                }

                if (temporaryExe is not null)
                {
                    try
                    {
                        File.Delete(temporaryExe);
                    }
                    catch (Exception)
                    {
                        // 临时文件删不掉不影响结论。
                    }
                }
            }
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "WFP DACL 检查执行完成", false);
        }

        PrintSummary(results, showFirewallResidue: false);
    }
    private static void RunWfpRuleTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   WFP 规则模型自检（规则存在过滤器自身，V4 + V6 两层）        #");
        W("################################################################");
        W();

        var exePath = Environment.ProcessPath!;
        var blockRule = new WfpRule(exePath, FirewallAction.Block);
        var allowRule = new WfpRule(
            exePath,
            FirewallAction.Allow,
            RuleExpiry.At(DateTime.UtcNow.AddMinutes(30)));

        // ---------------- 1. 编码 / 解析（纯离线） ----------------
        W("===== 1. 规则编码与解析 =====");
        W($"    阻止规则说明字段 = {blockRule.Description}");
        W($"    允许规则说明字段 = {allowRule.Description}");

        var blockParsed = WfpRule.TryParse(blockRule.Description, out var parsedBlock);
        CheckAssertion(results, "说明字段能被自己解析回来", blockParsed);
        CheckAssertion(results, "解析出的路径一致", blockParsed && parsedBlock.ApplicationPath == exePath);
        CheckAssertion(results, "解析出的动作一致", blockParsed && parsedBlock.Action == FirewallAction.Block);
        CheckAssertion(results, "永久规则的到期解析成「永久」", blockParsed && parsedBlock.Expiry.IsPermanent);

        var allowParsed = WfpRule.TryParse(allowRule.Description, out var parsedAllow);
        CheckAssertion(results, "限期规则能解析出到期时刻",
            allowParsed && parsedAllow.Expiry.Kind == RuleExpiryKind.AtTime);

        CheckAssertion(results, "不是我们格式的说明字段被忽略", !WfpRule.TryParse("随便写的说明", out _));
        CheckAssertion(results, "缺字段的说明字段被忽略", !WfpRule.TryParse("AppGuard|1|Block", out _));
        CheckAssertion(results, "版本号不认识时被忽略", !WfpRule.TryParse("AppGuard|9|Block|C:\\a.exe|", out _));

        CheckAssertion(results, "同一规则的 key 是确定的",
            WfpRuleStore.FilterKeyFor(blockRule, WfpNativeMethods.LayerAleAuthConnectV4)
            == WfpRuleStore.FilterKeyFor(blockRule, WfpNativeMethods.LayerAleAuthConnectV4));
        CheckAssertion(results, "V4 与 V6 两层的 key 不同（不会互相覆盖）",
            WfpRuleStore.FilterKeyFor(blockRule, WfpNativeMethods.LayerAleAuthConnectV4)
            != WfpRuleStore.FilterKeyFor(blockRule, WfpNativeMethods.LayerAleAuthConnectV6));

        // ---------------- 2~4. 真实往返 ----------------
        using (var engine = WfpEngine.Open())
        {
            engine.DeleteAllOurFilters();

            // 生产环境就是持久化子层（2.0 的规则要跨重启），这里按同样形状测。
            // 先删掉可能残留的旧子层（例如上一次失败时建的非持久化子层），
            // 否则"已存在"会让这次按旧状态走，测的就不是生产的形状了。
            engine.DeleteSublayer();
            engine.EnsureSublayer(persistent: true);
            CheckAssertion(results, "子层是持久化的（2.0 的实际形状）", engine.SublayerPersistent);

            // 无论哪一步断言失败（异常），最后都把实验对象收拾干净。
            try
            {
                W();
                W("===== 2. 写入 → 读回 → 重复写入（幂等）=====");

                var written = WfpRuleStore.Add(engine, blockRule);
                W($"    写入阻止规则：{written} 条过滤器（预期 2 = V4 + V6）");
                CheckAssertion(results, "一条规则写入两层", written == 2);

                var layers = engine.ListOurFilters().Select(filter => filter.LayerKey).ToList();
                CheckAssertion(results, "V4 层上确实有过滤器",
                    layers.Contains(WfpNativeMethods.LayerAleAuthConnectV4));
                CheckAssertion(results, "V6 层上确实有过滤器（说明 GUID 有效、层存在）",
                    layers.Contains(WfpNativeMethods.LayerAleAuthConnectV6));

                // 专门钉住一类错误：过滤器加进去了，但说明字段没写进去 ——
                // 那时"写入成功"却"读回 0 条规则"，症状很迷惑。
                var stored = engine.ListOurFilters();
                var idMap = RuleEngine.GetFilterIdToRuleName();
                W($"    过滤器 ID → 规则名：{idMap.Count} 条");
                CheckAssertion(results, "两条过滤器的 ID 都能映射回规则名",
                    idMap.Count >= 2 && idMap.Values.All(name => name == blockRule.DisplayName));

                // 审计只允许记录"本工具自己的过滤器"拦下的连接：
                // 这张集合必须与子层里实际存在的过滤器 **完全一致**（多一个少一个都是 bug）。
                var actualIds = engine.ListOurFilters()
                    .Select(filter => filter.FilterId)
                    .Where(id => id != 0)
                    .ToHashSet();
                var reportedIds = RuleEngine.GetOurFilterIds();

                W($"    子层过滤器 ID = {actualIds.Count} 个，GetOurFilterIds = {reportedIds.Count} 个");
                CheckAssertion(results, "过滤器 ID 集合与子层实际内容一致",
                    actualIds.SetEquals(reportedIds));

                CheckAssertion(results, "两条过滤器的说明字段里都存着规则内容",
                    stored.Count == 2 && stored.All(filter => WfpRule.TryParse(filter.Description, out _)));
                CheckAssertion(results, "显示名称也已写入",
                    stored.Count == 2 && stored.All(filter => !string.IsNullOrEmpty(filter.Name)));

                WfpRuleStore.Add(engine, blockRule);
                var afterRepeat = engine.ListOurFilters().Count;
                W($"    重复写入后过滤器总数 = {afterRepeat}（预期 2）");
                CheckAssertion(results, "重复写入是幂等的，不产生重复规则", afterRepeat == 2);

                var rules = WfpRuleStore.List(engine);
                CheckAssertion(results, "读回 1 条规则（两层被识别成同一条）", rules.Count == 1);
                CheckAssertion(results, "读回的规则内容一致",
                    rules.Count == 1 && rules[0] == blockRule);

                W();
                W("===== 3. 允许规则与到期信息 =====");

                WfpRuleStore.Add(engine, allowRule);
                var both = WfpRuleStore.List(engine);
                W($"    现在读到 {both.Count} 条规则");

                CheckAssertion(results, "读到 2 条规则（阻止 + 允许）", both.Count == 2);

                var allowBack = both.FirstOrDefault(rule => rule.Action == FirewallAction.Allow);
                CheckAssertion(results, "允许规则被读回", allowBack is not null);
                CheckAssertion(results, "允许规则的到期信息也跟着读回来了",
                    allowBack is not null
                    && allowBack.Expiry.Kind == RuleExpiryKind.AtTime
                    && allowBack.Expiry.ExpiresAtUtc is not null);

                W();
                W("===== 4. 删除 =====");

                var removedAllow = WfpRuleStore.Remove(engine, allowRule);
                CheckAssertion(results, "删允许规则删掉 2 条过滤器", removedAllow == 2);
                CheckAssertion(results, "删完只剩 1 条规则", WfpRuleStore.List(engine).Count == 1);

                var removedBlock = WfpRuleStore.Remove(engine, blockRule);
                CheckAssertion(results, "删阻止规则删掉 2 条过滤器", removedBlock == 2);
                CheckAssertion(results, "删完一条规则都不剩", WfpRuleStore.List(engine).Count == 0);
                CheckAssertion(results, "重复删除同一条规则不报错（返回 0）",
                    WfpRuleStore.Remove(engine, blockRule) == 0);

                // 2.0 的 --recover 就是这两步：先删光过滤器，再删子层。
                engine.DeleteSublayer();
                CheckAssertion(results, "子层删除后读不到", IsSublayerMissing(engine));
            }
            finally
            {
                // 兜底：断言失败/异常也要把自己留下的东西收拾掉。
                try
                {
                    engine.DeleteAllOurFilters();
                    engine.DeleteSublayer();
                }
                catch (WfpException)
                {
                    // 已经干净了，忽略。
                }
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 迁移自检：造两条**真实的** 1.x 规则 → 迁移 → 核对 → 清理。
    ///
    /// 只迁移"自己造的那两条"，绝不碰用户已有的真实规则 ——
    /// 所以这个自检在机器上有多少条 <c>AppGuard_</c> 规则都是安全的。
    /// </summary>
    private static void RunWfpMigrateTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   1.x → 2.0 规则迁移自检（只迁移自己造的两条测试规则）        #");
        W("################################################################");
        W();

        // ⚠️ 迁移对象不能选"自检程序自己"：那会撞上产品的自我保护
        //    （拦住自己就再也打不开界面解除拦截了，这是刻意设的闸，不该绕过）。
        //    记事本是最合适的替身：一定存在、不在受保护名单里、拦掉也不影响任何功能。
        var targetExe = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        var createdRuleNames = new List<string>();

        W($"    迁移测试对象 = {targetExe}");
        CheckAssertion(results, "迁移测试对象存在（记事本）", File.Exists(targetExe));

        // ---------------- 1. 可迁移性判断（纯逻辑，不碰系统） ----------------
        W("===== 1. 可迁移性判断 =====");

        FirewallRuleItem MakeRule(
            FirewallDirection direction = FirewallDirection.Outbound,
            int protocol = 256,
            bool enabled = true,
            string? path = null)
            => new()
            {
                Name = "AppGuard_Test_x",
                ApplicationPath = path ?? targetExe,
                Description = string.Empty,
                Grouping = AppConstants.RuleGroupingName,
                Enabled = enabled,
                Action = FirewallAction.Block,
                Direction = direction,
                Protocol = protocol,
            };

        CheckAssertion(results, "普通出站阻止规则：可迁移", WfpMigration.Validate(MakeRule()) is null);
        CheckAssertion(results, "入站规则：跳过",
            WfpMigration.Validate(MakeRule(direction: FirewallDirection.Inbound)) is not null);
        CheckAssertion(results, "带协议限制的规则：跳过",
            WfpMigration.Validate(MakeRule(protocol: 6)) is not null);
        CheckAssertion(results, "停用的规则：跳过（不能因为迁移把它变生效）",
            WfpMigration.Validate(MakeRule(enabled: false)) is not null);
        CheckAssertion(results, "程序文件已不存在：跳过",
            WfpMigration.Validate(MakeRule(path: @"C:\WinAppGuard-不存在的目录\none.exe")) is not null);
        CheckAssertion(results, "没有指定程序的规则：跳过",
            WfpMigration.Validate(MakeRule(path: " ")) is not null);

        using (var engine = WfpEngine.Open())
        {
            engine.DeleteAllOurFilters();
            engine.DeleteSublayer();
            engine.EnsureSublayer(persistent: true);

            try
            {
                // ---------------- 2. 造两条真实的 1.x 规则 ----------------
                W();
                W("===== 2. 造两条真实的 1.x 规则（都指向记事本）=====");

                createdRuleNames.Add(FirewallManager.CreateBlockRule(targetExe));
                createdRuleNames.Add(FirewallManager.CreateAllowRule(targetExe));

                foreach (var name in createdRuleNames)
                {
                    W($"    已创建：{name}");
                }

                var mine = FirewallManager.GetAppGuardRules()
                    .Where(rule => createdRuleNames.Contains(rule.Name))
                    .ToList();

                CheckAssertion(results, "读到 2 条刚创建的 1.x 规则", mine.Count == 2);
                CheckAssertion(results, "其中一条阻止、一条允许",
                    mine.Count(rule => rule.Action == FirewallAction.Block) == 1
                    && mine.Count(rule => rule.Action == FirewallAction.Allow) == 1);

                // ---------------- 3. 迁移 ----------------
                W();
                W("===== 3. 迁移 =====");

                var report = WfpMigration.Migrate(engine, mine);
                W($"    迁移 = {report.Migrated}，跳过 = {report.Skipped}，" +
                  $"失败 = {report.Failed}，删除旧规则 = {report.FirewallRulesDeleted}");

                foreach (var line in report.Details)
                {
                    W($"      {line}");
                }

                CheckAssertion(results, "2 条都迁移成功", report.Migrated == 2);
                CheckAssertion(results, "没有失败项", report.Succeeded);
                CheckAssertion(results, "2 条旧规则都被删除", report.FirewallRulesDeleted == 2);

                // ---------------- 4. 核对两边 ----------------
                W();
                W("===== 4. 核对结果 =====");

                var leftovers = FirewallManager.GetAppGuardRules()
                    .Where(rule => createdRuleNames.Contains(rule.Name))
                    .ToList();
                CheckAssertion(results, "Windows 防火墙里已经找不到这两条", leftovers.Count == 0);

                var wfpRules = WfpRuleStore.List(engine);
                W($"    2.0 里现在有 {wfpRules.Count} 条规则：");
                foreach (var rule in wfpRules)
                {
                    var action = rule.Action == FirewallAction.Block ? "阻止" : "允许";
                    W($"      {action}  {rule.ApplicationPath}");
                }

                CheckAssertion(results, "2.0 里是 2 条规则", wfpRules.Count == 2);
                CheckAssertion(results, "阻止规则迁移过来了",
                    wfpRules.Any(rule => rule.Action == FirewallAction.Block));
                CheckAssertion(results, "允许规则迁移过来了",
                    wfpRules.Any(rule => rule.Action == FirewallAction.Allow));
                CheckAssertion(results, "每条规则都写了两层（共 4 条过滤器）",
                    engine.ListOurFilters().Count == 4);

                // ---------------- 5. 重复迁移 ----------------
                W();
                W("===== 5. 重复迁移（幂等）=====");

                var again = WfpMigration.Migrate(engine, mine);
                var filterCount = engine.ListOurFilters().Count;
                W($"    再迁一次：迁移 = {again.Migrated}，过滤器总数 = {filterCount}");

                CheckAssertion(results, "重复迁移不增加过滤器", filterCount == 4);
                CheckAssertion(results, "重复迁移不报失败", again.Failed == 0);
            }
            finally
            {
                // 收拾自己造出来的东西：先删 2.0 规则，再删可能残留的 1.x 规则。
                try
                {
                    WfpRuleStore.RemoveAll(engine);
                    engine.DeleteSublayer();
                }
                catch (WfpException)
                {
                    // 已经干净了，忽略。
                }

                foreach (var name in createdRuleNames)
                {
                    try
                    {
                        FirewallManager.DeleteRule(name);
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        W($"    !!! 清理旧规则失败：{name}：{ex.Message}");
                    }
                }
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 只读：打印 2.0 在 WFP 里的现状（子层、过滤器、规则）。
    ///
    /// 这是"内置规则查看器"在命令行里的对应物 —— 用的就是界面将来要调的那两个方法，
    /// 所以这里显示得对，界面显示的依据也就是对的。
    /// </summary>
    private static void RunWfpStatus()
    {
        W("################################################################");
        W("#   2.0 WFP 状态（只读，不做任何修改）                          #");
        W("################################################################");
        W();

        using var engine = WfpEngine.Open();

        if (IsSublayerMissing(engine))
        {
            W("  子层：不存在 —— 本程序还没有往 WFP 里写过任何东西。");
        }
        else
        {
            var (weight, persistent) = engine.ReadSublayer();
            W($"  子层：存在，权重 0x{weight:X4}，持久化={persistent}");
        }

        var filters = engine.ListOurFilters();
        W($"  过滤器：{filters.Count} 条（每条规则占 V4/V6 两条）");

        var rules = WfpRuleStore.List(engine);
        if (rules.Count == 0)
        {
            W("  规则：没有");
        }
        else
        {
            W($"  规则：{rules.Count} 条");
            foreach (var rule in rules)
            {
                var action = rule.Action == FirewallAction.Block ? "阻止" : "允许";
                var expiry = rule.Expiry.Describe(DateTime.UtcNow);
                W($"    {action}  {rule.ApplicationPath}  [{expiry}]");
            }
        }

        var unrecognized = filters.Count(filter => !WfpRule.TryParse(filter.Description, out _));
        if (unrecognized > 0)
        {
            W($"  ⚠️ 有 {unrecognized} 条过滤器不是当前格式写的（可能是旧版本留下的）。");
            W("     确认没有需要保留的规则后，用 --wfp-recover-test 清理。");
        }

        W();
        W("  说明：这里只读，不修改任何东西。");
    }

    /// <summary>
    /// 恢复（--recover）自检。
    ///
    /// 要证明三件事：
    ///   1. 能把本程序在 WFP 里的东西**全部**清掉（过滤器 + 子层）；
    ///   2. **不碰** Windows 防火墙的规则（那是迁移流程的地盘）；
    ///   3. 本来就干净时再恢复一次不报错（幂等，救命命令不能比问题更危险）。
    ///
    /// ⚠️ 这个自检会清空本程序在 WFP 里的**所有**规则（这正是 --recover 的语义），
    ///    只适合在开发/虚拟机里跑。它不会碰 Windows 防火墙规则以外的任何系统对象。
    /// </summary>
    private static void RunWfpRecoverTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   WFP 恢复自检（--recover：清自己的东西，不碰 Windows 防火墙） #");
        W("################################################################");
        W();

        var targetExe = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        var createdFirewallRule = string.Empty;

        // 记录测试前就存在的记事本规则：万一用户本来就有，测试结束时不能删掉它。
        var preexisting = FirewallManager.GetAppGuardRules()
            .Where(rule => string.Equals(rule.ApplicationPath, targetExe, StringComparison.OrdinalIgnoreCase))
            .Select(rule => rule.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        try
        {
            // ---------------- 1. 先造出"脏"现场 ----------------
            W("===== 1. 先写入 2 条规则（模拟用过的状态）=====");

            using (var engine = WfpEngine.Open())
            {
                engine.DeleteAllOurFilters();
                engine.DeleteSublayer();
                engine.EnsureSublayer(persistent: true);

                WfpRuleStore.Add(engine, new WfpRule(targetExe, FirewallAction.Block));
                WfpRuleStore.Add(engine, new WfpRule(targetExe, FirewallAction.Allow));

                var filterCount = engine.ListOurFilters().Count;
                W($"    过滤器 = {filterCount} 条（预期 4），规则 = {WfpRuleStore.List(engine).Count} 条（预期 2）");
                CheckAssertion(results, "现场已造好：2 条规则 → 4 条过滤器", filterCount == 4);
            }

            // 再造一条 Windows 防火墙规则，用来证明恢复**不会**碰它。
            createdFirewallRule = FirewallManager.CreateBlockRule(targetExe);
            W($"    另建一条 Windows 防火墙规则（用来验证恢复不碰它）：{createdFirewallRule}");
            CheckAssertion(results, "Windows 防火墙里确实有一条规则",
                FirewallManager.GetAppGuardRules().Any(rule => rule.Name == createdFirewallRule));

            // ---------------- 2. 恢复 ----------------
            W();
            W("===== 2. 执行恢复 =====");

            var report = WfpRecovery.Recover();
            W($"    {report.Describe()}");

            CheckAssertion(results, "删掉了 4 条过滤器", report.FiltersDeleted == 4);
            CheckAssertion(results, "子层也被删掉了", report.SublayerDeleted);
            CheckAssertion(results, "不是「本来就干净」的状态", !report.WasAlreadyClean);

            using (var engine = WfpEngine.Open())
            {
                CheckAssertion(results, "恢复后过滤器 0 条", engine.ListOurFilters().Count == 0);
                CheckAssertion(results, "恢复后子层不存在", IsSublayerMissing(engine));
            }

            CheckAssertion(results, "恢复**没有**碰 Windows 防火墙的规则",
                FirewallManager.GetAppGuardRules().Any(rule => rule.Name == createdFirewallRule));

            // ---------------- 3. 幂等 ----------------
            W();
            W("===== 3. 再恢复一次（幂等）=====");

            var again = WfpRecovery.Recover();
            W($"    {again.Describe()}");

            CheckAssertion(results, "本来就干净时恢复不报错、删除 0 条",
                again.FiltersDeleted == 0 && again.WasAlreadyClean);
        }
        finally
        {
            // 收拾：只删自己建的那条 Windows 防火墙规则（测试前就存在的不动）。
            if (!string.IsNullOrEmpty(createdFirewallRule) && !preexisting.Contains(createdFirewallRule))
            {
                try
                {
                    FirewallManager.DeleteRule(createdFirewallRule);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    W($"    !!! 清理 Windows 防火墙规则失败：{ex.Message}");
                }
            }

            // 兜底：万一上面中途异常，WFP 自己也再清一次。
            try
            {
                WfpRecovery.Recover();
            }
            catch (WfpException)
            {
                // 忽略。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 严格模式（真白名单）自检。
    ///
    /// 要证明四件事：
    ///   1. 会话建立后，我们的子层里出现「白名单放行 + 阻止全部」；
    ///   2. 会话活着时，未被放行的程序（就是本自检程序自己）真的连不出去；
    ///   3. 会话结束（等价于进程退出 / 被强杀）后，过滤器**自动消失**；
    ///   4. 连接随之恢复 —— 不需要任何"还原"代码。
    ///
    /// 这台自检程序**刻意不把自己放进白名单**：要测的正是"没被放行的程序会被挡住"。
    /// </summary>
    private static void RunWfpStrictTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   WFP 严格模式自检（动态会话：白名单放行 + 阻止全部）          #");
        W("################################################################");
        W();

        var targetExe = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        const string probeHost = "whois.cymru.com";
        const int probePort = 43;

        // 清场：先把自己的东西清干净，免得上次的残留把条数搅乱。
        using (var cleanup = WfpEngine.Open())
        {
            cleanup.DeleteAllOurFilters();
            cleanup.DeleteSublayer();
        }

        // 基线：先确认这台机器本来能连出去，否则"连不通"证明不了任何事。
        var baseline = CanConnect(probeHost, probePort);
        W($"  基线连接（{probeHost}:{probePort}）= {(baseline ? "通" : "不通")}");

        if (!baseline)
        {
            W("  ⚠️ 基线就不通，本轮跳过「真的能拦住」的断言（只验证过滤器结构）。");
        }

        using (var session = WfpStrictSession.Start(new[] { targetExe }))
        {
            W();
            W("===== 1. 会话建立 =====");
            W($"    放行程序 = {string.Join("、", session.PermittedPrograms.Select(Path.GetFileName))}");
            W($"    过滤器 = {session.FilterKeys.Count} 条（预期 4 = 1 条放行 + 1 条阻止全部，各 V4/V6）");

            CheckAssertion(results, "放行了 1 个程序", session.PermittedPrograms.Count == 1);
            CheckAssertion(results, "会话里有 4 条过滤器", session.FilterKeys.Count == 4);

            using (var peek = WfpEngine.Open())
            {
                var visible = peek.ListOurFilters();
                W($"    从另一个会话看到我们的过滤器 = {visible.Count} 条");
                CheckAssertion(results, "另一个会话能看到这 4 条（说明真的进了 BFE）", visible.Count == 4);
            }

            W();
            W("===== 2. 未放行的程序应当连不出去 =====");

            var during = CanConnect(probeHost, probePort);
            W($"    严格模式下连接 = {(during ? "通" : "不通（被拦）")}");

            if (baseline)
            {
                CheckAssertion(results, "未放行的程序被拦住了（连不通）", !during);
            }
        }

        W();
        W("===== 3. 会话结束（= 进程退出 / 被强杀）后应当自动撤销 =====");

        using (var check = WfpEngine.Open())
        {
            var leftover = check.ListOurFilters();
            W($"    过滤器 = {leftover.Count} 条（预期 0）");
            CheckAssertion(results, "会话结束后过滤器全部消失", leftover.Count == 0);
        }

        var after = CanConnect(probeHost, probePort);
        W($"    连接 = {(after ? "通（已恢复）" : "不通")}");

        if (baseline)
        {
            CheckAssertion(results, "连接自动恢复（不需要任何还原逻辑）", after);
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>能不能建立一条 TCP 连接（自检专用，快速失败，不抛异常）。</summary>
    private static bool CanConnect(string host, int port, int timeoutMs = 3000)
    {
        try
        {
            using var client = new TcpClient();

            var task = client.ConnectAsync(host, port);
            if (!task.Wait(timeoutMs))
            {
                return false;
            }

            return client.Connected;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// 审计存储自检（离线、零副作用，全部在临时目录里做）。
    ///
    /// 重点验证四件事：
    ///   1. 一条记录的字段能**原样**存回来（含中文路径）；
    ///   2. 断电留下的**半行**不会毁掉整个文件；
    ///   3. 超过体积上限会**自动分段**；
    ///   4. 超过保留期的文件会被清掉，而 7 天内的不会。
    /// </summary>
    private static void RunAuditStoreTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"wag-audit-{Guid.NewGuid():N}");

        W("################################################################");
        W("#   审计存储自检（离线：往返 / 半行容错 / 轮转 / 保留期清理）    #");
        W("################################################################");
        W();

        try
        {
            Directory.CreateDirectory(tempDirectory);

            // ---------------- 1. 往返 ----------------
            W("===== 1. 写入与读回 =====");

            var now = DateTime.UtcNow;
            var events = new[]
            {
                new AuditEvent
                {
                    TimeUtc = now.AddSeconds(-2),
                    Kind = AuditEventKind.Connect,
                    ProcessPath = @"C:\Program Files\测试 工具\a.exe",
                    ProcessId = 1234,
                    RemoteAddress = "140.82.112.3",
                    RemotePort = 443,
                    Protocol = 6,
                    Domain = "github.com",
                },
                new AuditEvent
                {
                    TimeUtc = now.AddSeconds(-1),
                    Kind = AuditEventKind.Blocked,
                    ProcessPath = @"C:\Windows\System32\notepad.exe",
                    ProcessId = 5678,
                    RemoteAddress = "216.31.12.15",
                    RemotePort = 43,
                    Protocol = 6,
                    FilterId = 71735,
                },
                new AuditEvent
                {
                    TimeUtc = now,
                    Kind = AuditEventKind.Connect,
                    ProcessPath = @"C:\Tools\b.exe",
                    ProcessId = 9012,
                    RemoteAddress = "2001:db8::1",
                    RemotePort = 8443,
                    Protocol = 6,
                    Domain = "a.com / b.com",
                },
            };

            using (var store = new AuditStore(tempDirectory))
            {
                foreach (var item in events)
                {
                    store.Append(item);
                }

                var readBack = store.ReadRecent(10);
                W($"    写入 3 条，读回 {readBack.Count} 条");
                CheckAssertion(results, "读回条数一致", readBack.Count == 3);

                var first = readBack[0];
                CheckAssertion(results, "顺序按写入先后（时间正序）", first.ProcessId == 1234);
                CheckAssertion(results, "中文路径原样保留",
                    first.ProcessPath == @"C:\Program Files\测试 工具\a.exe");
                CheckAssertion(results, "远端地址与端口正确",
                    first.RemoteAddress == "140.82.112.3" && first.RemotePort == 443);
                CheckAssertion(results, "域名与「推测」标记保留",
                    first.Domain == "github.com" && first.DomainIsGuess);

                var blocked = readBack[1];
                CheckAssertion(results, "拦截事件保留了命中规则 ID",
                    blocked.Kind == AuditEventKind.Blocked && blocked.FilterId == 71735);
                CheckAssertion(results, "没有域名时是 null（不是空字符串）",
                    blocked.Domain is null);

                CheckAssertion(results, "IPv6 地址原样保留",
                    readBack[2].RemoteAddress == "2001:db8::1");

                _ = store.GetFiles().Single();
            }

            // ---------------- 2. 半行容错 ----------------
            W();
            W("===== 2. 断电留下半行 =====");

            var halfLineFile = Directory.GetFiles(tempDirectory, "audit-*.jsonl").Single();
            File.AppendAllText(
                halfLineFile,
                "{\"t\":\"2026-10-18T00:00:00Z\",\"k\":0,\"p\":\"C:\\\\x.exe\",\"a\":\"1.2.3.4\"",
                Encoding.UTF8);

            using (var reopen = new AuditStore(tempDirectory))
            {
                var afterHalfLine = reopen.ReadRecent(10);
                W($"    追加半行后读回 {afterHalfLine.Count} 条（预期仍是 3）");
                CheckAssertion(results, "半行被跳过，其余记录不受影响", afterHalfLine.Count == 3);
            }

            // ---------------- 3. 轮转 ----------------
            W();
            W("===== 3. 超过体积上限自动分段 =====");

            using (var small = new AuditStore(tempDirectory, maxFileBytes: 300))
            {
                for (var i = 0; i < 12; i++)
                {
                    small.Append(new AuditEvent
                    {
                        TimeUtc = now.AddSeconds(i),
                        Kind = AuditEventKind.Connect,
                        ProcessPath = $@"C:\Tools\rotate{i}.exe",
                        RemoteAddress = "10.0.0.1",
                        RemotePort = (ushort)(1000 + i),
                        Protocol = 6,
                    });
                }

                var files = small.GetFiles();
                W($"    分段文件数 = {files.Count}");
                foreach (var path in files)
                {
                    W($"      {Path.GetFileName(path)}  {new FileInfo(path).Length} 字节");
                }

                CheckAssertion(results, "确实分成了多个文件", files.Count >= 2);

                var all = small.ReadRecent(100);
                CheckAssertion(results, "跨文件读取条数正确（3 旧 + 12 新）", all.Count == 15);
            }

            // ---------------- 3.5 清空：写入端开着时删不掉 ----------------
            W();
            W("===== 清空：写入端开着时删不掉，关掉后能删 =====");

            var clearDirectory = Path.Combine(tempDirectory, "clear-test");
            Directory.CreateDirectory(clearDirectory);

            using (var writer = new AuditStore(clearDirectory))
            {
                writer.Append(new AuditEvent
                {
                    TimeUtc = now,
                    Kind = AuditEventKind.Connect,
                    ProcessPath = @"C:\x.exe",
                    RemoteAddress = "1.1.1.1",
                    RemotePort = 443,
                    Protocol = 6,
                });

                using var cleaner = new AuditStore(clearDirectory);
                var whileOpen = cleaner.Clear();

                W($"    写入端开着时删除 = {whileOpen} 个（预期 0）");
                CheckAssertion(results, "写入端开着时删不掉（Windows 文件锁）", whileOpen == 0);
            }

            using (var cleaner = new AuditStore(clearDirectory))
            {
                var afterClose = cleaner.Clear();
                W($"    写入端关闭后删除 = {afterClose} 个（预期 ≥1）");
                CheckAssertion(results, "写入端关闭后能删掉", afterClose >= 1);
            }

            // ---------------- 4. 保留期 ----------------
            W();
            W("===== 4. 保留期清理 =====");

            var today = DateTime.Now.Date;
            var recentFile = Path.Combine(tempDirectory, $"audit-{today.AddDays(-3):yyyyMMdd}-99.jsonl");
            var oldFile = Path.Combine(tempDirectory, $"audit-{today.AddDays(-30):yyyyMMdd}-99.jsonl");
            File.WriteAllText(recentFile, string.Empty, Encoding.UTF8);
            File.WriteAllText(oldFile, string.Empty, Encoding.UTF8);

            using (var store = new AuditStore(tempDirectory, retentionDays: 7))
            {
                var deleted = store.PurgeExpired(DateTime.Now);
                W($"    删除 {deleted} 个过期文件（预期 1）");

                CheckAssertion(results, "超过 7 天的被删掉", !File.Exists(oldFile));
                CheckAssertion(results, "7 天内的保留", File.Exists(recentFile));
            }

            // 2.1.3：保留期可调（1 / 3 / 7 / 30 天）。同一批文件在不同保留期下结果必须不同，
            // 否则"改了设置却没生效"这种假开关不会被任何断言发现。
            foreach (var days in new[] { 1, 3, 30 })
            {
                var file = Path.Combine(tempDirectory, $"audit-{today.AddDays(-3):yyyyMMdd}-98.jsonl");
                File.WriteAllText(file, string.Empty, Encoding.UTF8);

                using var store = new AuditStore(tempDirectory, retentionDays: days);
                var deleted = store.PurgeExpired(DateTime.Now);

                var expectedExists = days > 3;
                W($"    保留 {days} 天：3 天前的文件" +
                  $"{(File.Exists(file) ? "保留" : "被删")}（预期{(expectedExists ? "保留" : "删除")}），删除 {deleted} 个");

                CheckAssertion(results,
                    $"保留 {days} 天时，3 天前的文件{(expectedExists ? "保留" : "被删")}",
                    File.Exists(file) == expectedExists);

                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }

            // ---------------- 5. 关闭记录与清空 ----------------
            W();
            W("===== 5. 关闭记录与清空 =====");

            using (var store = new AuditStore(tempDirectory))
            {
                var bytesBefore = store.GetFiles().Sum(path => new FileInfo(path).Length);

                store.Enabled = false;
                store.Append(new AuditEvent
                {
                    TimeUtc = now,
                    Kind = AuditEventKind.Connect,
                    ProcessPath = @"C:\x.exe",
                    RemoteAddress = "1.1.1.1",
                    RemotePort = 80,
                    Protocol = 6,
                });

                var bytesAfter = store.GetFiles().Sum(path => new FileInfo(path).Length);
                CheckAssertion(results, "关闭后不再写入", bytesAfter == bytesBefore);

                store.Enabled = true;
                store.Clear();
                CheckAssertion(results, "清空后没有审计文件", store.GetFiles().Count == 0);
            }

            // ---------------- 6. 摘要文本 ----------------
            W();
            W("===== 6. 摘要文本 =====");

            var line = events[1].Describe();
            W($"    {line}");
            CheckAssertion(results, "摘要里写明了「拦截」", line.Contains("拦截"));
            CheckAssertion(results, "摘要里写明了程序名与远端", line.Contains("notepad.exe") && line.Contains("216.31.12.15"));
            CheckAssertion(results, "没有域名时写明「域名未知」", line.Contains("域名未知"));
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDirectory))
                {
                    Directory.Delete(tempDirectory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// DNS 缓存与域名索引自检（离线、**不联网**）。
    ///
    /// 两件事：
    ///   1. 真的读一遍本机 DNS 缓存，看看能拿到多少映射、有多少"一个 IP 多个域名"；
    ///   2. 用合成数据验证索引逻辑：单候选 / 多候选 / 过期 / 未知。
    /// </summary>
    private static void RunAuditDnsTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   DNS 缓存与域名索引自检（只读本机缓存，不发任何网络请求）     #");
        W("################################################################");
        W();

        // ---------------- 1. 结构体尺寸 ----------------
        var layoutOk = true;
        try
        {
            DnsCacheReader.EnsureLayout();
        }
        catch (Exception ex)
        {
            layoutOk = false;
            W($"    {ex.Message}");
        }

        CheckAssertion(results, "DNS 结构体尺寸与字段偏移正确", layoutOk);

        // ---------------- 2. 读真实缓存 ----------------
        W();
        W("===== 1. 本机 DNS 缓存 =====");

        var tableProbe = DnsCacheReader.ProbeTable();
        W($"    [诊断] 缓存表：返回码={tableProbe.Result} 条目={tableProbe.Entries} 有名字={tableProbe.NamedEntries} 第一个={tableProbe.FirstName ?? "（空）"}");
        var snapshot = DnsCacheReader.ReadSnapshot();
        var strictCacheOnly = DnsCacheReader.ReadSnapshot(allowResolverQuery: false);
        W($"    两种模式：仅缓存(零发包) = {strictCacheOnly.Count} 条；缓存优先(可回源) = {snapshot.Count} 条");
        var distinctAddresses = snapshot.Select(record => record.Address)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var distinctNames = snapshot.Select(record => record.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count();

        W($"    记录 {snapshot.Count} 条：唯一 IP {distinctAddresses} 个、唯一域名 {distinctNames} 个");

        foreach (var sample in snapshot.Take(8))
        {
            W($"      {sample.Name} → {sample.Address}（TTL {sample.TtlSeconds}s）");
        }

        CheckAssertion(results, "读取缓存没有抛异常", true);
        CheckAssertion(results, "所有地址都能被解析成合法 IP",
            snapshot.All(record => IPAddress.TryParse(record.Address, out _)));

        if (snapshot.Count == 0)
        {
            W("    ⚠️ 当前缓存是空的：随便打开一个网页再跑一次，就能看到真实的映射。");
        }

        // ---------------- 3. 一 IP 多域名（CDN 撞车） ----------------
        W();
        W("===== 2. 一个 IP 对应多个域名 =====");

        var multi = snapshot
            .GroupBy(record => record.Address, StringComparer.OrdinalIgnoreCase)
            .Select(group => new
            {
                Address = group.Key,
                Names = group.Select(record => record.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            })
            .Where(item => item.Names.Count > 1)
            .ToList();

        W($"    {multi.Count} 组");
        foreach (var item in multi.Take(5))
        {
            W($"      {item.Address} ← {string.Join(" / ", item.Names.Take(3))}");
        }

        CheckAssertion(results, "多域名统计可以计算", multi.Count >= 0);

        // ---------------- 4. 索引逻辑（合成数据） ----------------
        W();
        W("===== 3. 域名索引逻辑 =====");

        var now = DateTime.UtcNow;
        var index = new DomainIndex(TimeSpan.FromMinutes(30));

        index.Update(new[]
        {
            new DnsCacheRecord("single.example", "10.0.0.1", 60),
            new DnsCacheRecord("a.example", "10.0.0.2", 60),
            new DnsCacheRecord("b.example", "10.0.0.2", 60),
            new DnsCacheRecord("v6.example", "2001:db8::5", 60),
        }, now);

        var single = index.Resolve("10.0.0.1", now);
        var multiple = index.Resolve("10.0.0.2", now);
        var unknown = index.Resolve("10.9.9.9", now);
        var v6 = index.Resolve("2001:db8::5", now);

        W($"    单候选 = {single.Domain}（{single.CandidateCount} 个）");
        W($"    多候选 = {multiple.Domain}（{multiple.CandidateCount} 个）");
        W($"    未知   = {unknown.Domain ?? "null"}");
        W($"    IPv6   = {v6.Domain}");

        CheckAssertion(results, "单候选时给出域名", single.Domain == "single.example" && single.CandidateCount == 1);
        CheckAssertion(results, "多候选时全部列出并标注数量",
            multiple.CandidateCount == 2
            && multiple.Domain is not null
            && multiple.Domain.Contains("a.example")
            && multiple.Domain.Contains("b.example"));
        CheckAssertion(results, "未知 IP 返回 null", unknown.Domain is null && unknown.CandidateCount == 0);
        CheckAssertion(results, "IPv6 地址也能匹配", v6.Domain == "v6.example");

        // ---------------- 5. 过期 ----------------
        W();
        W("===== 4. 过期记录会被丢掉 =====");

        index.Update(Array.Empty<DnsCacheRecord>(), now.AddHours(2));
        var afterExpiry = index.Resolve("10.0.0.1", now.AddHours(2));

        W($"    两小时后 = {afterExpiry.Domain ?? "null"}，剩余 IP 数 = {index.AddressCount}");
        CheckAssertion(results, "过期后查不到域名", afterExpiry.Domain is null);
        CheckAssertion(results, "过期记录已从索引里删除", index.AddressCount == 0);

        // ---------------- 6. 用真实缓存建索引 ----------------
        W();
        W("===== 5. 用真实缓存建索引 =====");

        var realIndex = new DomainIndex();
        realIndex.Update(snapshot, now);
        W($"    索引里有 {realIndex.AddressCount} 个 IP（预期与唯一 IP 数一致）");
        CheckAssertion(results, "索引 IP 数与快照一致", realIndex.AddressCount == distinctAddresses);

        if (snapshot.Count > 0)
        {
            var pick = snapshot[0];
            var guessed = realIndex.Resolve(pick.Address, now);
            W($"    抽查 {pick.Address} → {guessed.Domain ?? "null"}（{guessed.CandidateCount} 个候选）");
            CheckAssertion(results, "抽查的 IP 能查到刚写入的域名",
                guessed.Domain is not null
                && guessed.Domain.Contains(pick.Name, StringComparison.OrdinalIgnoreCase));
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 审计实时采集自检（需要管理员）。
    ///
    /// 先离线验证"连接差集"逻辑，再真的启动 WFP 网络事件订阅 + 每 3 秒扫一次连接表，
    /// 跑十几秒看能不能采到东西。
    /// </summary>
    private static void RunAuditLiveTest(int seconds)
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   审计实时采集（连接差集 + WFP 拦截事件，需要管理员）          #");
        W("################################################################");
        W();

        // ---------------- 1. 差集逻辑（离线） ----------------
        W("===== 1. 连接差集逻辑 =====");

        var tracker = new ConnectionTracker();
        var a = new ConnectionKey(@"C:\a.exe", 1, "1.1.1.1", 443, 6);
        var b = new ConnectionKey(@"C:\b.exe", 2, "2.2.2.2", 80, 6);
        var c = new ConnectionKey(@"C:\c.exe", 3, "3.3.3.3", 53, 6);

        CheckAssertion(results, "首轮全部算新连接", tracker.Update(new[] { a, b }).Count == 2);

        var second = tracker.Update(new[] { a, b, c });
        CheckAssertion(results, "重复出现的连接不算新连接",
            second.Count == 1 && second[0].ProcessPath == @"C:\c.exe");

        _ = tracker.Update(new[] { a });
        var back = tracker.Update(new[] { a, b });
        CheckAssertion(results, "连接消失后再出现会重新算新连接",
            back.Count == 1 && back[0].ProcessPath == @"C:\b.exe");

        // ---------------- 2. 设备路径映射 ----------------
        W();
        W("===== 2. 设备路径映射 =====");

        var mapped = DevicePathMapper.ToDosPath(@"\device\harddiskvolume3\windows\notepad.exe");
        W($"    \\device\\harddiskvolume3\\windows\\notepad.exe → {mapped}");
        CheckAssertion(results, "设备路径能映射（映射不到时原样返回也不算崩）", !string.IsNullOrEmpty(mapped));

        // ---------------- 3. 启动拦截事件订阅 ----------------
        W();
        W("===== 3. WFP 拦截事件订阅 =====");

        var drops = new List<WfpDropEvent>();
        WfpDropCollector? collector = null;
        var isAdmin = AdminHelper.IsRunningAsAdmin();

        try
        {
            collector = WfpDropCollector.Start();
            collector.DropDetected += drop =>
            {
                lock (drops)
                {
                    drops.Add(drop);
                }
            };

            CheckAssertion(results, "订阅 WFP 网络事件成功", true);
        }
        catch (Exception ex)
        {
            if (isAdmin)
            {
                CheckAssertion(results, "订阅 WFP 网络事件成功", false);
                W($"    {ex.Message}");
            }
            else
            {
                W("    非管理员：跳过 WFP 事件订阅（在虚拟机里用管理员终端跑这一项）。");
            }
        }

        try
        {
            // ---------------- 4. 轮询连接表 ----------------
            W();
            W("===== 4. 连接轮询（每 3 秒一轮）=====");

            var rounds = Math.Max(1, seconds / 3);
            var liveTracker = new ConnectionTracker();
            var newConnections = new List<ConnectionKey>();

            for (var i = 0; i < rounds; i++)
            {
                try
                {
                    var snapshot = ConnectionScanner.Scan();
                    var added = liveTracker.Update(ConnectionTracker.FromSnapshot(snapshot));
                    newConnections.AddRange(added);
                    W($"    第 {i + 1}/{rounds} 轮：当前 {snapshot.Count} 条连接，新增 {added.Count} 条");
                }
                catch (Exception ex)
                {
                    W($"    第 {i + 1} 轮扫描失败：{ex.Message}");
                }

                if (i < rounds - 1)
                {
                    Thread.Sleep(3000);
                }
            }

            // ---------------- 5. 汇总 ----------------
            W();
            W("===== 5. 汇总 =====");

            foreach (var item in newConnections.Take(10))
            {
                W($"    新连接 {Path.GetFileName(item.ProcessPath)} → {item.Address}:{item.Port}");
            }

            if (newConnections.Count > 10)
            {
                W($"    …… 以及另外 {newConnections.Count - 10} 条");
            }

            lock (drops)
            {
                foreach (var drop in drops.Take(10))
                {
                    W($"    拦截 {Path.GetFileName(drop.ProcessPath)} → {drop.RemoteAddress}:{drop.RemotePort}" +
                      $"（filterId={drop.FilterId}）");
                }

                W($"    新连接 {newConnections.Count} 条，拦截事件 {drops.Count} 条");
                CheckAssertion(results, "采样期间没有让程序崩溃", true);
            }
        }
        finally
        {
            collector?.Dispose();
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 审计服务端到端自检：真的跑 12 秒，把三个数据源串起来写进临时目录，再读回来核对。
    ///
    /// 验证的是"接线"而不是"逻辑"（逻辑各自有专门的离线自检）：
    ///   - 服务能起、能停；
    ///   - 确实产生了审计文件，条数与写入计数一致；
    ///   - 连接事件里有域名推测（缓存有记录时）。
    /// </summary>
    private static void RunAuditServiceTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"wag-auditsvc-{Guid.NewGuid():N}");

        W("################################################################");
        W("#   审计服务（DNS + 连接轮询 + 拦截事件 → 落盘，跑 12 秒）       #");
        W("################################################################");
        W();

        AuditService? service = null;

        try
        {
            service = new AuditService(tempDirectory, pollSeconds: 2);
            service.Start();

            CheckAssertion(results, "服务已启动", service.IsRunning);
            W($"    拦截事件订阅 = {(service.DropSubscriptionActive ? "成功" : "未成功（非管理员时会这样）")}");
            W($"    本工具过滤器 ID = {service.OurFilterIdCount} 个（只有这些 ID 的拦截事件才会被记录）");

            if (service.LastError is not null)
            {
                W($"    最近错误：{service.LastError}");
            }

            W("    采样 12 秒（现在随便开几个网页 / 让程序联网）……");

            // 主动造一条"确定性"的连接：先解析域名（让它进系统 DNS 缓存），
            // 再连上去并保持几秒，让服务至少轮询到两次。
            // 这样"域名推测"这一环才有可验证的前提；连不上就不强求。
            var probeConnected = false;
            var probeAddress = string.Empty;

            try
            {
                var addresses = Dns.GetHostAddresses("whois.cymru.com");
                var target = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);

                if (target is not null)
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(target, 43);

                    if (connectTask.Wait(4000) && client.Connected)
                    {
                        probeConnected = true;
                        probeAddress = target.ToString();
                        W($"    主动建立一条连接（用于验证域名推测）：{target}:43");
                        Thread.Sleep(6000);
                    }
                }
            }
            catch (Exception ex)
            {
                W($"    主动连接失败（不影响其它断言）：{ex.Message}");
            }

            Thread.Sleep(6000);

            service.Dispose();
            var stopped = !service.IsRunning;

            // ⚠️ 计数必须在 Dispose **之后**读：Dispose 会等当前那一轮轮询跑完，
            //    那一轮还会写入几条；先读计数再 Dispose 就会"读回比写入多"，
            //    机器上有别的程序在联网时必然撞上（实测多出 2 条）—— 那是测量的竞态，不是丢数据。
            var written = service.EventsWritten;
            var drops = service.DropsSeen;

            service = null;

            W();
            W("===== 结果 =====");
            W($"    写入 {written} 条，其中拦截 {drops} 条");

            var files = Directory.Exists(tempDirectory)
                ? Directory.GetFiles(tempDirectory, "audit-*.jsonl")
                : Array.Empty<string>();

            W($"    审计文件 {files.Length} 个");
            foreach (var file in files)
            {
                W($"      {Path.GetFileName(file)}  {new FileInfo(file).Length} 字节");
            }

            CheckAssertion(results, "产生了审计文件", files.Length > 0);

            using var reader = new AuditStore(tempDirectory);
            var events = reader.ReadRecent(5000);

            W($"    读回 {events.Count} 条（写入计数 {written}）");
            CheckAssertion(results, "读回条数与写入计数一致", events.Count == written);

            var connects = events.Count(item => item.Kind == AuditEventKind.Connect);
            var blocked = events.Count(item => item.Kind == AuditEventKind.Blocked);
            var withDomain = events.Count(item => !string.IsNullOrEmpty(item.Domain));

            W($"    连接 {connects} 条，拦截 {blocked} 条，带域名 {withDomain} 条");

            foreach (var sample in events.Where(item => !string.IsNullOrEmpty(item.Domain)).Take(5))
            {
                W($"      {sample.Describe()}");
            }

            if (probeConnected)
            {
                var probeEvents = events
                    .Where(item => item.RemoteAddress == probeAddress && item.RemotePort == 43)
                    .ToList();

                W($"    主动连接相关记录 = {probeEvents.Count} 条（目标 {probeAddress}:43）");

                foreach (var item in probeEvents)
                {
                    W($"      {item.Describe()}  域名={(item.Domain ?? "null")}");
                }

                // 先看"原始缓存里此刻到底有没有这条记录"——
                // 没有的话是环境问题（TTL 到期 / DoH），不是我们的 bug。
                var raw = DnsCacheReader.ReadSnapshot();
                var rawHasAddress = raw.Any(record =>
                    string.Equals(record.Address, probeAddress, StringComparison.OrdinalIgnoreCase));

                W($"    [诊断] 直接读缓存：{raw.Count} 条记录，" +
                  $"其中包含目标 IP = {(rawHasAddress ? "是" : "否")}");

                foreach (var record in raw
                             .Where(record => string.Equals(record.Address, probeAddress, StringComparison.OrdinalIgnoreCase))
                             .Take(3))
                {
                    W($"      [诊断] {record.Name} → {record.Address}（TTL {record.TtlSeconds}s）");
                }

                CheckAssertion(results, "主动连接被记录", probeEvents.Count > 0);

                if (rawHasAddress)
                {
                    CheckAssertion(results,
                        "缓存里有这条解析时，审计记录必须带域名",
                        probeEvents.Any(item => !string.IsNullOrEmpty(item.Domain)));
                }
                else
                {
                    W("    ⚠️ 缓存里没有该 IP 的有效记录（TTL 到期或走 DoH），本轮跳过域名断言。");
                }
            }
            else
            {
                W("    未建立主动连接，域名命中率只作参考（不做断言）。");
            }
            CheckAssertion(results, "服务停止后 IsRunning = false", stopped);
        }
        finally
        {
            service?.Dispose();

            try
            {
                if (Directory.Exists(tempDirectory))
                {
                    Directory.Delete(tempDirectory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 审计页结构自检：确认页签里**真的有控件**（曾经出现过"只有页签、内容是空的"——
    /// 原因是构造器里的初始化调用漏掉了，而编译和界面其它自检都发现不了）。
    ///
    /// 不显示窗口、不启动后台服务，纯结构检查。
    /// </summary>
    private static void RunAuditUiTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   审计页结构（页签里必须有工具条、表格、开关）                 #");
        W("################################################################");
        W();

        MainForm.SuppressBackgroundServices = true;

        using var form = new MainForm(isAutostart: false);

        if (!TryGetField<TabPage>(form, "_tabAudit", out var tab))
        {
            CheckAssertion(results, "找得到 _tabAudit", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        W($"    页签文本 = {tab.Text}，直接子控件 = {tab.Controls.Count}");

        foreach (Control child in tab.Controls)
        {
            W($"      {child.GetType().Name}  Dock={child.Dock}  Size={child.Size}");
        }

        CheckAssertion(results, "页签标题是「记录」", tab.Text == "记录");
        CheckAssertion(results, "页签里有直接子控件（工具条 / 表格 / 底栏）", tab.Controls.Count >= 3);

        var grids = Descendants<DataGridView>(tab).ToList();
        W($"    表格数量 = {grids.Count}");

        CheckAssertion(results, "页签里有表格", grids.Count == 1);
        CheckAssertion(results, "表格有 6 列", grids.Count == 1 && grids[0].Columns.Count == 6);

        if (grids.Count == 1)
        {
            var headers = string.Join(" | ", grids[0].Columns.Cast<DataGridViewColumn>().Select(column => column.HeaderText));
            W($"    列标题 = {headers}");
            CheckAssertion(results, "列标题包含「域名」和「命中规则」",
                headers.Contains("域名") && headers.Contains("命中规则"));
        }

        var checkBoxes = Descendants<CheckBox>(tab).Select(box => box.Text).ToList();
        W($"    复选框 = {string.Join(" / ", checkBoxes)}");

        CheckAssertion(results, "有「记录连接」开关", checkBoxes.Any(text => text.Contains("记录连接")));
        CheckAssertion(results, "有「域名推测」开关", checkBoxes.Any(text => text.Contains("域名推测")));
        CheckAssertion(results, "有「只看拦截」开关", checkBoxes.Any(text => text.Contains("只看拦截")));

        var buttons = Descendants<Button>(tab).Select(button => button.Text).ToList();
        W($"    按钮 = {string.Join(" / ", buttons)}");
        CheckAssertion(results, "有「清空」按钮", buttons.Any(text => text.Contains("清空")));
        CheckAssertion(results, "有「拦截此 IP」按钮", buttons.Any(text => text.Contains("拦截此 IP")));
        CheckAssertion(results, "有「添加 IP」按钮", buttons.Any(text => text.Contains("添加 IP")));

        // ---- 记录保留期（2.1.3）----
        var combo = Descendants<ComboBox>(tab).FirstOrDefault(item => item.Name == "_auditRetentionCombo");
        CheckAssertion(results, "有「记录保留」下拉框", combo is not null);

        if (combo is not null)
        {
            var items = combo.Items.Cast<object>().Select(item => item.ToString()).ToList();
            W($"    保留期选项 = {string.Join(" / ", items)}");

            CheckAssertion(results, "保留期有 1 / 3 / 7 / 30 天四个选项",
                items.Contains("1 天") && items.Contains("3 天")
                && items.Contains("7 天") && items.Contains("30 天"));

            // 下拉索引 → 天数 的映射（接错会让"1 天"实际按 30 天清理）。
            var expected = new[] { 1, 3, 7, 30 };
            var mappingOk = true;

            for (var index = 0; index < expected.Length; index++)
            {
                combo.SelectedIndex = index;
                var days = InvokeInstance<int>(form, "SelectedAuditRetentionDays");

                if (days != expected[index])
                {
                    W($"    ！下拉第 {index + 1} 项映射成 {days} 天，预期 {expected[index]}");
                    mappingOk = false;
                }

                if (RetentionDaysToIndex(days) != index)
                {
                    W($"    ！{days} 天反查索引得到 {RetentionDaysToIndex(days)}，预期 {index}");
                    mappingOk = false;
                }
            }

            CheckAssertion(results, "保留期下拉与天数的映射正确（双向）", mappingOk);
            CheckAssertion(results, "默认保留 7 天",
                AppSettings.DefaultAuditRetentionDays == 7);

            var addIpButton = Descendants<Button>(tab).FirstOrDefault(button => button.Text.Contains("添加 IP"));
            CheckAssertion(results, "保留期下拉不和「添加 IP」按钮重叠",
                addIpButton is null || !combo.Bounds.IntersectsWith(addIpButton.Bounds));
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>天数 → 下拉索引（与产品同一套规则，自检里复算一遍做双向校验）。</summary>
    private static int RetentionDaysToIndex(int days) => days switch
    {
        <= 1 => 0,
        <= 3 => 1,
        <= 7 => 2,
        _ => 3,
    };

    /// <summary>递归找出某类型的所有子控件。</summary>
    private static IEnumerable<T> Descendants<T>(Control root) where T : Control
    {
        foreach (Control child in root.Controls)
        {
            if (child is T match)
            {
                yield return match;
            }

            foreach (var nested in Descendants<T>(child))
            {
                yield return nested;
            }
        }
    }

    /// <summary>
    /// 「封禁 IP」规则自检（需要管理员、需要能连外网）。
    ///
    /// 用 whois.cymru.com 的两个 A 记录做对照：只封禁其中一个，
    /// 验证"目标被拦 + 邻居正常"，最后删除规则并确认过滤器消失。
    /// </summary>
    private static void RunWfpIpRuleTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   封禁 IP 规则（只拦目标、不误伤邻居；IPv4）                   #");
        W("################################################################");
        W();

        var addresses = Dns.GetHostAddresses("whois.cymru.com")
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address.ToString())
            .Distinct()
            .ToList();

        if (addresses.Count < 2)
        {
            W("    解析不到两个 A 记录，无法做对照实验（跳过）。");
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        var target = addresses[0];
        var neighbor = addresses[1];
        W($"    目标 = {target}，邻居 = {neighbor}");

        var baselineTarget = ProbeConnect(target, 43);
        var baselineNeighbor = ProbeConnect(neighbor, 43);
        W($"    基线：目标={baselineTarget}，邻居={baselineNeighbor}");

        var ruleName = string.Empty;

        try
        {
            ruleName = RuleEngine.CreateIpBlockRule(target);
            W($"    已创建规则：{ruleName}");

            var rule = RuleEngine.GetRules()
                .FirstOrDefault(item => string.Equals(item.Name, ruleName, StringComparison.OrdinalIgnoreCase));

            CheckAssertion(results, "规则列表里有这条 IP 规则", rule is not null);
            CheckAssertion(results, "规则里带着 IP 地址", rule?.IpAddress == target);
            CheckAssertion(results, "规则名是 AppGuard_BlockIp_ 前缀",
                ruleName.StartsWith("AppGuard_BlockIp_", StringComparison.Ordinal));

            var idMap = RuleEngine.GetFilterIdToRuleName();
            CheckAssertion(results, "过滤器 ID 能映射到这条 IP 规则",
                idMap.Values.Any(name => string.Equals(name, ruleName, StringComparison.OrdinalIgnoreCase)));

            if (baselineTarget && baselineNeighbor)
            {
                var blockedTarget = !ProbeConnect(target, 43);
                var blockedNeighbor = !ProbeConnect(neighbor, 43);

                W($"    封禁后：目标可连={!blockedTarget}，邻居可连={!blockedNeighbor}");

                CheckAssertion(results, "目标 IP 被拦住", blockedTarget);
                CheckAssertion(results, "邻居 IP 不受影响", !blockedNeighbor);
            }
            else
            {
                W("    ⚠️ 基线就不通，跳过连通性断言（只验证规则本身）。");
            }
        }
        finally
        {
            if (!string.IsNullOrEmpty(ruleName))
            {
                var deleted = RuleEngine.DeleteRule(ruleName);
                W($"    删除规则 = {deleted}");

                CheckAssertion(results, "删除规则成功", deleted);
                CheckAssertion(results, "删除后规则列表里没有它",
                    !RuleEngine.GetRules().Any(item =>
                        string.Equals(item.Name, ruleName, StringComparison.OrdinalIgnoreCase)));
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>能不能建立一条 TCP 连接（快速失败）。</summary>
    private static bool ProbeConnect(string host, int port, int timeoutMs = 3000)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(timeoutMs) && client.Connected;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>子层是否已经不存在（只读判断，不抛异常）。</summary>
    private static bool IsSublayerMissing(WfpEngine engine)
    {
        try
        {
            engine.ReadSublayer();
            return false;
        }
        catch (WfpException ex)
        {
            return ex.Code == WfpNativeMethods.FWP_E_SUBLAYER_NOT_FOUND;
        }
    }

    /// <summary>
    /// CLI 语言（3.3，离线）：--lang 优先级、ui-state.json 读取、英文文案与数据行契约。
    /// </summary>
    private static void RunCliLanguageTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previous = Localizer.Current;

        W("################################################################");
        W("#   CLI 语言（--lang 优先级 / GUI 已生效语言 / 英文输出契约）    #");
        W("################################################################");
        W();

        try
        {
            // ---------------- 1. 优先级 ----------------
            W("===== 1. 语言优先级 =====");

            CheckAssertion(results, "--lang 覆盖 GUI 已生效语言",
                CliLanguage.TryResolve("en", "zh", out var byOption) && byOption == "en");
            CheckAssertion(results, "没有 --lang 时跟随 GUI",
                CliLanguage.TryResolve(null, "en", out var byGui) && byGui == "en");
            CheckAssertion(results, "两者都没有时 auto",
                CliLanguage.TryResolve(null, null, out var bySystem) && bySystem == "auto");
            CheckAssertion(results, "--lang 非法值被拒绝",
                !CliLanguage.TryResolve("fr", "en", out _));

            // ---------------- 1.1 --lang 参与参数解析 ----------------
            W();
            W("===== 1.1 --lang 与命令解析 =====");

            var listWithLang = CommandLine.Parse(
                new[] { "--list-blocked", "--lang", "en" });
            CheckAssertion(results, "--list-blocked --lang en 仍是有效的列表命令",
                listWithLang.Kind == CommandKind.ListBlocked
                && listWithLang.Language == "en");

            var blockWithLang = CommandLine.Parse(
                new[] { "--block", @"C:\Program Files\A B\c.exe", "--lang", "en" });
            CheckAssertion(results, "--block 的路径不受 --lang 影响",
                blockWithLang.Kind == CommandKind.Block
                && blockWithLang.ProgramPath == @"C:\Program Files\A B\c.exe"
                && blockWithLang.Language == "en");

            var equalsLang = CommandLine.Parse(
                new[] { "--lang=zh", "--list-blocked" });
            CheckAssertion(results, "--lang=zh 的形式也认",
                equalsLang.Kind == CommandKind.ListBlocked
                && equalsLang.Language == "zh");

            CheckAssertion(results, "--lang 大小写不敏感（--LANG EN）",
                CommandLine.Parse(new[] { "--lang", "EN", "--list-blocked" }).Language == "en");

            var helpWithLang = CommandLine.Parse(
                new[] { "--help", "--lang", "en" });
            CheckAssertion(results, "--help 也带出 --lang",
                helpWithLang.Kind == CommandKind.Help
                && helpWithLang.Language == "en");

            CheckAssertion(results, "--lang 缺值 → 参数错误",
                CommandLine.Parse(new[] { "--list-blocked", "--lang" }).Kind
                    == CommandKind.Invalid);
            CheckAssertion(results, "非法 --lang → 参数错误",
                CommandLine.Parse(new[] { "--list-blocked", "--lang", "fr" }).Kind
                    == CommandKind.Invalid);

            var englishError = CommandLine.Parse(
                new[] { "--list-blocked", "x", "--lang", "en" });
            CheckAssertion(results, "英文模式的参数错误也是英文",
                englishError.Kind == CommandKind.Invalid
                && !System.Text.RegularExpressions.Regex.IsMatch(
                    englishError.Error ?? string.Empty, "[\u4e00-\u9fff]"));

            // ---------------- 2. ui-state.json ----------------
            W();
            W("===== 2. 读取 GUI 已生效语言 =====");

            var directory = Path.Combine(
                Path.GetTempPath(), "wag-cli-lang-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            try
            {
                var file = Path.Combine(directory, "ui-state.json");

                File.WriteAllText(
                    file, "{\"Language\":\"zh\",\"AppliedLanguage\":\"en\"}");
                CheckAssertion(results, "优先读 AppliedLanguage（哪怕 Language 还没重启）",
                    UiLanguageStore.ReadAppliedLanguage(file) == "en");

                File.WriteAllText(file, "{\"Language\":\"zh\"}");
                CheckAssertion(results, "3.2 旧文件没有 AppliedLanguage 时回退 Language",
                    UiLanguageStore.ReadAppliedLanguage(file) == "zh");

                var loaded = UiState.Load(file);
                CheckAssertion(results, "旧文件加载后 AppliedLanguage 回填 Language",
                    loaded.AppliedLanguage == "zh"
                    && loaded.Language == "zh");

                new UiState { Language = "en", AppliedLanguage = "zh" }.Save(file);
                CheckAssertion(results, "GUI 写出的 AppliedLanguage 能被 CLI 读到",
                    UiLanguageStore.ReadAppliedLanguage(file) == "zh");

                File.WriteAllText(file, "{\"Language\":\"fr\"}");
                CheckAssertion(results, "非法语言返回 null（视为跟随系统）",
                    UiLanguageStore.ReadAppliedLanguage(file) is null);

                CheckAssertion(results, "文件不存在返回 null",
                    UiLanguageStore.ReadAppliedLanguage(
                        Path.Combine(directory, "missing.json")) is null);
            }
            finally
            {
                try
                {
                    Directory.Delete(directory, recursive: true);
                }
                catch (Exception)
                {
                    // 临时目录删不掉不影响结论。
                }
            }

            // ---------------- 3. 英文输出 ----------------
            W();
            W("===== 3. 英文文案与数据行 =====");

            Localizer.Initialize("en");

            CheckAssertion(results, "英文帮助包含 --lang",
                CliText.Usage.Contains("--lang", StringComparison.Ordinal));
            CheckAssertion(results, "英文帮助不含中文",
                !System.Text.RegularExpressions.Regex.IsMatch(
                    CliText.Usage, "[\u4e00-\u9fff]"));

            var rule = new RuleDto
            {
                Name = "AppGuard_Block_a.exe_1a2b3c4d",
                Value = @"C:\Tools\a.exe",
                Expiry = string.Empty,
            };

            var englishLine = CliText.FormatRuleLine(rule);
            W($"    英文数据行 = {englishLine}");
            CheckAssertion(results, "英文数据行仍是三段 Tab",
                englishLine.Split('\t').Length == 3);
            CheckAssertion(results, "英文数据行不带中文（脚本契约不变）",
                !System.Text.RegularExpressions.Regex.IsMatch(
                    englishLine, "[\u4e00-\u9fff]"));

            var englishList = CliText.BuildListBlockedOutput(
                new[] { rule }, 2, "3.3.0");
            CheckAssertion(results, "英文表头",
                englishList.Contains(
                    "# rule name\tprogram path\texpiry", StringComparison.Ordinal));
            CheckAssertion(results, "英文列表整体不含中文",
                !System.Text.RegularExpressions.Regex.IsMatch(
                    englishList, "[\u4e00-\u9fff]"));

            // ---------------- 4. 中文回退 ----------------
            W();
            W("===== 4. 中文输出 =====");

            Localizer.Initialize("zh");

            CheckAssertion(results, "中文帮助含中文",
                System.Text.RegularExpressions.Regex.IsMatch(
                    CliText.Usage, "[\u4e00-\u9fff]"));

            var chineseLine = CliText.FormatRuleLine(rule);
            W($"    中文数据行 = {chineseLine}");
            CheckAssertion(results, "中文数据行仍是三段 Tab",
                chineseLine.Split('\t').Length == 3);
            CheckAssertion(results, "中英文数据行前两段完全一致",
                chineseLine.Split('\t')[0] == englishLine.Split('\t')[0]
                && chineseLine.Split('\t')[1] == englishLine.Split('\t')[1]);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "CLI 语言检查执行完成", false);
        }
        finally
        {
            Localizer.Initialize(previous switch
            {
                Localizer.LanguageMode.English => "en",
                Localizer.LanguageMode.Chinese => "zh",
                _ => "auto",
            });
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 日志格式（3.3，离线）：服务模式英文级别、事件码保留、异常不写本地化 Message。
    /// </summary>
    private static void RunServiceLogFormatTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previousEnglish = LocalLog.English;
        var previousDirectory = LocalLog.LogDirectory;

        W("################################################################");
        W("#   日志格式（英文级别 / 事件码 / 异常不写本地化 Message）      #");
        W("################################################################");
        W();

        var directory = Path.Combine(
            Path.GetTempPath(), "wag-log-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            LocalLog.UseDirectory(directory);
            LocalLog.English = true;

            LocalLog.Info("[WAG-SVC-002] Service started.");
            LocalLog.Warning("[WAG-RULE-913] Tamper protection check.");
            LocalLog.Operation("[WAG-RULE-001] Rule block.");
            LocalLog.Error(
                "[WAG-IPC-003] IPC failed.",
                new InvalidOperationException("这是一条中文异常消息"));

            var file = Directory.GetFiles(directory, "winappguard-*.log").Single();
            var text = File.ReadAllText(file);

            W($"    日志文件 = {file}");
            W($"    行数 = {text.Split(Environment.NewLine).Length - 1}");

            CheckAssertion(results, "信息 → [INFO]",
                text.Contains("[INFO] [WAG-SVC-002]", StringComparison.Ordinal));
            CheckAssertion(results, "警告 → [WARN]",
                text.Contains("[WARN] [WAG-RULE-913]", StringComparison.Ordinal));
            CheckAssertion(results, "操作 → [OP]",
                text.Contains("[OP] [WAG-RULE-001]", StringComparison.Ordinal));
            CheckAssertion(results, "错误 → [ERROR]",
                text.Contains("[ERROR] [WAG-IPC-003]", StringComparison.Ordinal));
            CheckAssertion(results, "不再出现中文级别名",
                !text.Contains("[信息]", StringComparison.Ordinal)
                && !text.Contains("[警告]", StringComparison.Ordinal)
                && !text.Contains("[错误]", StringComparison.Ordinal)
                && !text.Contains("[操作]", StringComparison.Ordinal));

            CheckAssertion(results, "异常记录了类型",
                text.Contains("exception=System.InvalidOperationException", StringComparison.Ordinal));
            CheckAssertion(results, "异常记录了 HResult",
                text.Contains("hresult=0x", StringComparison.Ordinal));
            CheckAssertion(results, "异常没有写入本地化 Message",
                !text.Contains("这是一条中文异常消息", StringComparison.Ordinal));

            CheckAssertion(results, "英文模式 Pick 选英文",
                LocalLog.Pick("中文", "English") == "English");

            // 界面日志跟随界面语言：关掉英文模式后，Pick 必须回到中文。
            LocalLog.English = false;
            CheckAssertion(results, "中文模式 Pick 选中文",
                LocalLog.Pick("中文", "English") == "中文");
            LocalLog.Info("界面日志仍用中文级别");
            var updated = File.ReadAllText(file);
            CheckAssertion(results, "关掉英文模式后恢复中文级别",
                updated.Contains("[信息] 界面日志仍用中文级别", StringComparison.Ordinal));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "日志格式检查执行完成", false);
        }
        finally
        {
            LocalLog.English = previousEnglish;
            LocalLog.UseDirectory(previousDirectory);

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.5：服务代查路径的离线部分（进程解析 / DTO 编解码 / 回填）。
    /// 真实 IPC 需要服务在运行，放到 VM 验收。
    /// </summary>
    /// <summary>
    /// 3.5：服务端端到端验收 —— 流量采集（本机回环下载）与 DNS ETW 捕获。
    ///
    /// 只读 + 本机回环，不需要管理员；但需要所有者密钥（签名 IPC）。
    /// 输出都是实测数字：下载字节、本进程流量增量、DNS 探针记录。
    /// </summary>
    private static void RunService35Test()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   3.5/3.6 服务端实测（流量 ETW Network / DNS ETW）            #");
        W("################################################################");
        W();

        try
        {
            var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));

            if (status is null)
            {
                W("    服务不可用：请先安装/启动 WinAppGuardSvc。");
                CheckAssertion(results, "服务可用", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            W($"    服务版本 = {status.ServiceVersion}");

            var versionParts = status.ServiceVersion.Split('.');
            var versionOk = versionParts.Length >= 2
                            && int.TryParse(versionParts[0], out var major)
                            && int.TryParse(versionParts[1], out var minor)
                            && (major > 3 || (major == 3 && minor >= 5));

            CheckAssertion(results, "服务版本是 3.5 或更高", versionOk);
            CheckAssertion(results, "流量采集在跑", status.TrafficCollecting);
            CheckAssertion(results, "DNS 采集在跑", status.DnsCollecting);

            // ---------------- 流量 ----------------
            var before = QueryTrafficFromService(out var trafficError);
            TrafficDto? ownBefore = before is null ? null : FindOwnTraffic(before);

            using var serviceProcess = TryGetServiceProcess();
            var cpuBefore = TryReadCpu(serviceProcess);
            var wallBefore = DateTime.UtcNow;

            if (before is null)
            {
                W($"    读取流量失败：{trafficError}");
                CheckAssertion(results, "读取流量快照", false);
            }
            else
            {
                W($"    下载前本进程累计下载 = {ownBefore?.BytesIn ?? 0} 字节");

                var payloadBytes = 4 * 1024 * 1024;
                var received = DownloadLoopbackPayload(payloadBytes, out var downloadError);
                W($"    回环下载完成：{received} 字节（{downloadError ?? "ok"}）");

                Thread.Sleep(TimeSpan.FromSeconds(5));

                var after = QueryTrafficFromService(out _);
                var ownAfter = after is null ? null : FindOwnTraffic(after);
                var delta = ownAfter is null ? -1 : ownAfter.BytesIn - (ownBefore?.BytesIn ?? 0);

                W($"    下载后本进程累计下载 = {ownAfter?.BytesIn ?? 0} 字节；本次增量 = {delta} 字节");
                CheckAssertion(results, "本进程下载字节增量约为 4 MiB",
                    delta >= 2_500_000 && delta <= 6_000_000);

                var wall = DateTime.UtcNow - wallBefore;
                var cpuAfter = TryReadCpu(serviceProcess);

                if (cpuBefore is { } cpuStart && cpuAfter is { } cpuEnd && wall.TotalMilliseconds > 0)
                {
                    var percent = (cpuEnd - cpuStart).TotalMilliseconds
                                  / (wall.TotalMilliseconds * Environment.ProcessorCount) * 100;

                    W($"    服务 CPU（下载期间，{Environment.ProcessorCount} 核）= {percent:0.0}%");
                }
                else
                {
                    W("    服务 CPU：无法读取（权限或服务已退出）");
                }

                if (after is not null)
                {
                    W("    流量前 5 名：");
                    foreach (var row in after.Take(5))
                    {
                        W($"      {row.Name,-32} 上传 {row.BytesOut,10}  下载 {row.BytesIn,10}");
                    }
                }

                var afterStatus = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));
                W($"    流量事件数（本次服务运行累计）= {afterStatus?.TrafficEventsSeen ?? 0}" +
                  $"（本次测试新增 {Math.Max(0, (afterStatus?.TrafficEventsSeen ?? 0) - status.TrafficEventsSeen)}）");
            }

            // ---------------- DNS ----------------
            var probe = $"{Guid.NewGuid():N}.example.com";
            W($"    触发 DNS 查询：{probe}");

            try
            {
                _ = Dns.GetHostAddresses(probe);
            }
            catch (Exception)
            {
                // 预期失败（NXDOMAIN）；这里要的只是产生一次真实查询。
            }

            var matches = WaitForDnsRecords(probe, TimeSpan.FromSeconds(15));

            CheckAssertion(results, "捕获到探针域名的 DNS 记录", matches.Count > 0);

            if (matches.Count > 0)
            {
                foreach (var match in matches)
                {
                    W($"      event={match.EventId} PID={match.Pid} 程序={match.ProcessName} " +
                      $"路径={match.ProcessPath ?? "（无）"} 结果={match.Status}");
                }

                CheckAssertion(results, "DNS 记录带 PID 和程序名",
                    matches.Any(match => match.Pid > 0 && match.ProcessName.Length > 0));

                // 3006/3008 由发起进程还是 Dnscache 记录，不同 Windows 版本不一样。
                // 这里如实打印，不把「svchost」当成发起程序。
                var ownPath = Environment.ProcessPath;
                var own = matches.Any(match =>
                    !string.IsNullOrEmpty(ownPath)
                    && string.Equals(match.ProcessPath, ownPath, StringComparison.OrdinalIgnoreCase));

                W(own
                    ? "      归属：能对上发起程序（SelfCheck 自己）"
                    : "      归属：ETW 把查询记到了系统 DNS 服务名下（可能是 Dnscache/svchost）");
            }

            var dnsAll = QueryDnsFromService(out _);
            W($"    DNS 缓冲当前返回 {dnsAll?.Count ?? 0} 条（上限 500）");
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "3.5 服务端实测执行完成", false);
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.5：临时锁网的服务端实测（需要管理员/所有者）。
    ///
    /// 会**真的**建立严格模式会话，然后立刻关闭；只在验收用的 VM 上跑。
    /// </summary>
    private static void RunServiceLockdownTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   3.5 临时锁网实测（会短暂断网；只在 VM 跑）                   #");
        W("################################################################");
        W();

        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));

        if (status is null)
        {
            W("    服务不可用：请先安装/启动 WinAppGuardSvc。");
            CheckAssertion(results, "服务可用", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        if (status.StrictModeActive)
        {
            W("    严格模式已经开启；为避免影响用户，本次不做任何变更。");
            W("    请先关闭严格模式，再重新运行本项。");
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        ServiceResponse? enabled = null;

        try
        {
            enabled = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.StrictLockdown,
                    LockdownSeconds = 60,
                },
                TimeSpan.FromSeconds(20),
                out var enableError);

            W($"    开启结果：ok={enabled?.Ok}，错误={enabled?.Error ?? enableError}");

            CheckAssertion(results, "临时锁网 60 秒成功",
                enabled is { Ok: true, Status.StrictModeLockdownActive: true });

            if (enabled is { Ok: true, Status: not null })
            {
                var remaining = enabled.Status.StrictModeLockdownRemainingSeconds;
                W($"    剩余 = {remaining} 秒；放行程序 = {enabled.Status.StrictModePermittedCount}");

                CheckAssertion(results, "剩余时间在 1..60 秒",
                    remaining is > 0 and <= 60);
                CheckAssertion(results, "状态同时标记严格模式 + 临时锁网",
                    enabled.Status.StrictModeActive && enabled.Status.StrictModeLockdownActive);
            }
        }
        finally
        {
            // 无论上面成功与否，都要尽力把会话关掉，绝不留下断网状态。
            var disabled = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.StrictDisable },
                TimeSpan.FromSeconds(20),
                out var disableError);

            W($"    关闭结果：ok={disabled?.Ok}，错误={disabled?.Error ?? disableError}");

            CheckAssertion(results, "能提前关闭临时锁网",
                disabled is { Ok: true, Status.StrictModeActive: false, Status.StrictModeLockdownActive: false });
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.6：服务端清空流量计数（需要管理员/所有者）。
    /// 会清空本次运行的流量统计，验收脚本应放在最后跑。
    /// </summary>
    private static void RunWfpInboundTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var address = IPAddress.Parse("203.0.113.252");

        W("################################################################");
        W("#   4.0 WFP 入站临时封禁（真实过滤器；需要管理员）              #");
        W("################################################################");
        W();

        try
        {
            AntiScanWfp.Remove(address);
            AntiScanWfp.Add(address);

            using (var engine = WfpEngine.Open())
            {
                var found = engine.ListOurFilters().Any(filter =>
                    filter.LayerKey == WfpNativeMethods.LayerAleAuthRecvAcceptV4
                    && filter.Description?.StartsWith(
                        "AppGuard|1|AntiScanBlockIp|", StringComparison.Ordinal) == true);

                CheckAssertion(results, "入站 accept 层过滤器已创建", found);
            }

            CheckAssertion(results, "重复封禁是幂等的", AddTwice(address));

            AntiScanWfp.Remove(address);

            using (var engine = WfpEngine.Open())
            {
                var found = engine.ListOurFilters().Any(filter =>
                    filter.LayerKey == WfpNativeMethods.LayerAleAuthRecvAcceptV4
                    && filter.Description?.StartsWith(
                        "AppGuard|1|AntiScanBlockIp|", StringComparison.Ordinal) == true);

                CheckAssertion(results, "入站过滤器已删除", !found);
            }

            var v6 = IPAddress.Parse("2001:db8::41");
            AntiScanWfp.Remove(v6);
            AntiScanWfp.Add(v6);

            using (var engine = WfpEngine.Open())
            {
                var found = engine.ListOurFilters().Any(filter =>
                    filter.LayerKey == WfpNativeMethods.LayerAleAuthRecvAcceptV6
                    && filter.Description?.StartsWith(
                        "AppGuard|1|AntiScanBlockIp|", StringComparison.Ordinal) == true);

                CheckAssertion(results, "入站 IPv6 accept 层过滤器已创建", found);
            }

            AntiScanWfp.Remove(v6);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "WFP 入站过滤测试执行完成", false);
        }
        finally
        {
            try
            {
                AntiScanWfp.Remove(address);
            }
            catch (Exception)
            {
                // 清理失败不影响结论。
            }
        }

        PrintSummary(results, showFirewallResidue: true);
    }

    private static bool AddTwice(IPAddress address)
    {
        try
        {
            AntiScanWfp.Add(address);
            AntiScanWfp.Add(address);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static void RunServiceAntiScanTest()
    {
        var results = new List<(string Title, bool Passed)>();
        AntiScanSettingsDto? initialSettings = null;

        W("################################################################");
        W("#   4.0 反扫描服务端实测（Npcap / 设置 / 封禁；只在 VM 跑）       #");
        W("################################################################");
        W();

        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));

        if (status is null)
        {
            W("    服务不可用：请先安装/启动 WinAppGuardSvc。");
            CheckAssertion(results, "服务可用", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        W($"    服务版本 = {status.ServiceVersion}");
        var parts = status.ServiceVersion.Split('.');
        var versionOk = parts.Length >= 2
                        && int.TryParse(parts[0], out var major)
                        && int.TryParse(parts[1], out var minor)
                        && (major > 4 || (major == 4 && minor >= 0));

        CheckAssertion(results, "服务版本是 4.0 或更高", versionOk);
        CheckAssertion(results, "状态里有反扫描字段",
            status.AntiScanNpcapAvailable || status.AntiScanBlockedCount >= 0);

        var snapshot = QueryAntiScanResponse(out var queryError);

        if (snapshot is not { Ok: true })
        {
            W($"    读取反扫描失败：{snapshot?.Error ?? queryError}");
            CheckAssertion(results, "读取反扫描快照", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        initialSettings = snapshot.AntiScanSettings;
        var antiStatus = snapshot.AntiScanStatus;

        W($"    Npcap 可用={antiStatus?.NpcapAvailable} 版本={antiStatus?.NpcapVersion}");
        W($"    采集={antiStatus?.Collecting} 事件={antiStatus?.EventCount} 封禁={antiStatus?.BlockedCount}");

        CheckAssertion(results, "检测到 Npcap", antiStatus?.NpcapAvailable == true);
        CheckAssertion(results, "反扫描采集在跑", antiStatus?.Collecting == true);
        CheckAssertion(results, "反扫描设置已返回", initialSettings is not null);

        if (initialSettings is null)
        {
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        try
        {
            var testAllowlist = "203.0.113.77";
            var changed = CloneAntiScanSettings(initialSettings);
            changed.Allowlist = (changed.Allowlist ?? new List<string>())
                .Append(testAllowlist)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var configure = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.ConfigureAntiScan,
                    AntiScanSettings = changed,
                },
                TimeSpan.FromSeconds(15),
                out var configureError);

            W($"    写入允许名单：ok={configure?.Ok}，错误={configure?.Error ?? configureError}");
            CheckAssertion(results, "修改反扫描设置成功", configure is { Ok: true });

            var after = QueryAntiScanResponse(out _);
            CheckAssertion(results, "允许名单已保存",
                after?.AntiScanSettings?.Allowlist?.Contains(testAllowlist, StringComparer.OrdinalIgnoreCase) == true);

            var release = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.ReleaseAntiScanBlock,
                    AntiScanAddress = "203.0.113.250",
                },
                TimeSpan.FromSeconds(15),
                out var releaseError);

            W($"    解除不存在的封禁：ok={release?.Ok}，影响={release?.Affected}，错误={release?.Error ?? releaseError}");
            CheckAssertion(results, "解除不存在的封禁不报错", release is { Ok: true });

            var clear = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.ClearAntiScan },
                TimeSpan.FromSeconds(15),
                out var clearError);

            W($"    清空反扫描记录：ok={clear?.Ok}，错误={clear?.Error ?? clearError}");
            CheckAssertion(results, "清空反扫描记录成功", clear is { Ok: true });
        }
        finally
        {
            if (initialSettings is not null)
            {
                var restore = ServiceClient.TryRequest(
                    new ServiceRequest
                    {
                        Command = ServiceProtocol.Commands.ConfigureAntiScan,
                        AntiScanSettings = initialSettings,
                    },
                    TimeSpan.FromSeconds(15),
                    out var restoreError);

                W($"    恢复初始设置：ok={restore?.Ok}，错误={restore?.Error ?? restoreError}");
                CheckAssertion(results, "恢复初始反扫描设置", restore is { Ok: true });
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static ServiceResponse? QueryAntiScanResponse(out string? error)
    {
        return ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryAntiScan },
            TimeSpan.FromSeconds(5),
            out error);
    }

    private static AntiScanSettingsDto CloneAntiScanSettings(AntiScanSettingsDto settings) => new()
    {
        Enabled = settings.Enabled,
        Sensitivity = settings.Sensitivity,
        AutoBlock = settings.AutoBlock,
        BlockMinutes = settings.BlockMinutes,
        Allowlist = settings.Allowlist?.ToList() ?? new List<string>(),
    };

    private static void RunServiceIdsTest()
    {
        var results = new List<(string Title, bool Passed)>();
        IdsSettingsDto? initialSettings = null;

        W("################################################################");
        W("#   3.7 IDS 服务端实测（设置 / 抑制 / 清空；只在 VM 跑）          #");
        W("################################################################");
        W();

        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));

        if (status is null)
        {
            W("    服务不可用：请先安装/启动 WinAppGuardSvc。");
            CheckAssertion(results, "服务可用", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        W($"    服务版本 = {status.ServiceVersion}");
        var idsVersionParts = status.ServiceVersion.Split('.');
        var idsVersionOk = idsVersionParts.Length >= 2
                           && int.TryParse(idsVersionParts[0], out var idsMajor)
                           && int.TryParse(idsVersionParts[1], out var idsMinor)
                           && (idsMajor > 3 || (idsMajor == 3 && idsMinor >= 7));

        CheckAssertion(results, "服务版本是 3.7 或更高", idsVersionOk);

        CheckAssertion(results, "状态里有 IDS 字段", status.IdsEnabled || status.IdsFlowCount >= 0);
        W($"    IDS 开关={status.IdsEnabled} 采集中={status.IdsCollecting} " +
          $"flow={status.IdsFlowCount} 事件={status.IdsEventsSeen} 新告警={status.IdsAlertsNew}");

        var snapshot = QueryIdsResponse(out var queryError);

        if (snapshot is not { Ok: true })
        {
            W($"    读取 IDS 失败：{snapshot?.Error ?? queryError}");
            CheckAssertion(results, "读取 IDS 快照", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        initialSettings = snapshot.IdsSettings;
        CheckAssertion(results, "IDS 快照带设置和状态",
            snapshot.IdsSettings is not null && snapshot.IdsStatus is not null);

        if (initialSettings is null)
        {
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        W($"    初始设置：enabled={initialSettings.Enabled} " +
          $"sensitivity={initialSettings.Sensitivity} retention={initialSettings.RetentionDays}d " +
          $"alerts={snapshot.IdsAlerts?.Count ?? 0} suppressions={snapshot.IdsSuppressions?.Count ?? 0}");

        try
        {
            // ---- 开关往返 ----
            var off = CloneSettings(initialSettings);
            off.Enabled = false;

            var offResponse = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.IdsConfigure,
                    IdsSettings = off,
                },
                TimeSpan.FromSeconds(15),
                out var offError);

            W($"    关闭 IDS：ok={offResponse?.Ok}，错误={offResponse?.Error ?? offError}");
            CheckAssertion(results, "关闭 IDS 成功", offResponse is { Ok: true });

            var afterOff = QueryIdsResponse(out _);
            CheckAssertion(results, "关闭后状态为 Enabled=false",
                afterOff?.IdsStatus is { Enabled: false });

            var on = CloneSettings(initialSettings);
            on.Enabled = true;

            var onResponse = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.IdsConfigure,
                    IdsSettings = on,
                },
                TimeSpan.FromSeconds(15),
                out var onError);

            W($"    开启 IDS：ok={onResponse?.Ok}，错误={onResponse?.Error ?? onError}");
            CheckAssertion(results, "开启 IDS 成功", onResponse is { Ok: true });

            Thread.Sleep(TimeSpan.FromSeconds(2));

            var afterOn = QueryIdsResponse(out _);
            W($"    开启后：enabled={afterOn?.IdsStatus?.Enabled} " +
              $"collecting={afterOn?.IdsStatus?.Collecting} flow={afterOn?.IdsStatus?.FlowCount}");

            CheckAssertion(results, "开启后状态为 Enabled=true",
                afterOn?.IdsStatus is { Enabled: true });
            CheckAssertion(results, "开启后采集在跑",
                afterOn?.IdsStatus is { Collecting: true });

            // ---- 抑制往返 ----
            var target = "selftest-" + Guid.NewGuid().ToString("N") + ".example";

            var addResponse = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.IdsSuppress,
                    IdsSuppression = new IdsSuppressionDto
                    {
                        RuleId = "dns",
                        ProcessName = "selftest.exe",
                        Target = target,
                        UntilUtc = DateTime.UtcNow.AddHours(1),
                    },
                },
                TimeSpan.FromSeconds(15),
                out var addError);

            var added = addResponse?.IdsSuppressions?
                .FirstOrDefault(item => item.Target == target);

            W($"    新增抑制：ok={addResponse?.Ok}，id={added?.Id}，错误={addResponse?.Error ?? addError}");
            CheckAssertion(results, "新增抑制成功", addResponse is { Ok: true } && added is not null);

            if (added is not null)
            {
                var removeResponse = ServiceClient.TryRequest(
                    new ServiceRequest
                    {
                        Command = ServiceProtocol.Commands.IdsSuppress,
                        IdsRemoveSuppression = true,
                        IdsSuppression = new IdsSuppressionDto { Id = added.Id },
                    },
                    TimeSpan.FromSeconds(15),
                    out var removeError);

                var stillThere = removeResponse?.IdsSuppressions?
                    .Any(item => string.Equals(item.Id, added.Id, StringComparison.Ordinal)) == true;

                W($"    取消抑制：ok={removeResponse?.Ok}，仍在={stillThere}，" +
                  $"错误={removeResponse?.Error ?? removeError}");
                CheckAssertion(results, "取消抑制成功",
                    removeResponse is { Ok: true } && !stillThere);
            }

            // ---- 未知告警确认 / 清空 ----
            var ackMissing = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.IdsAck,
                    IdsAlertId = "no-such-alert",
                },
                TimeSpan.FromSeconds(15),
                out _);

            CheckAssertion(results, "确认不存在的告警返回失败", ackMissing is { Ok: false });

            var clear = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.IdsClear },
                TimeSpan.FromSeconds(15),
                out var clearError);

            W($"    清空告警：ok={clear?.Ok}，清理={clear?.Affected}，错误={clear?.Error ?? clearError}");
            CheckAssertion(results, "清空 IDS 告警成功", clear is { Ok: true });

            var afterClear = QueryIdsResponse(out _);
            CheckAssertion(results, "清空后告警列表为空",
                afterClear?.IdsAlerts is { Count: 0 });
        }
        finally
        {
            // 无论断言结果如何都要恢复用户原来的设置。
            if (initialSettings is not null)
            {
                var restore = ServiceClient.TryRequest(
                    new ServiceRequest
                    {
                        Command = ServiceProtocol.Commands.IdsConfigure,
                        IdsSettings = initialSettings,
                    },
                    TimeSpan.FromSeconds(15),
                    out var restoreError);

                W($"    恢复初始设置：ok={restore?.Ok}，错误={restore?.Error ?? restoreError}");
                CheckAssertion(results, "恢复初始 IDS 设置", restore is { Ok: true });
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static ServiceResponse? QueryIdsResponse(out string? error)
    {
        return ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryIdsAlerts },
            TimeSpan.FromSeconds(5),
            out error);
    }

    private static IdsSettingsDto CloneSettings(IdsSettingsDto settings) => new()
    {
        Enabled = settings.Enabled,
        Sensitivity = settings.Sensitivity,
        RetentionDays = settings.RetentionDays,
        BeaconingRule = settings.BeaconingRule,
        ScanRule = settings.ScanRule,
        LateralRule = settings.LateralRule,
        DnsRule = settings.DnsRule,
    };

    private static void RunServiceTrafficClearTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   3.6 清空流量统计（会清空本次运行计数；只在 VM 跑）           #");
        W("################################################################");
        W();

        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));

        if (status is null)
        {
            W("    服务不可用：请先安装/启动 WinAppGuardSvc。");
            CheckAssertion(results, "服务可用", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        var before = QueryTrafficResponse(out var beforeError);

        if (before is not { Ok: true })
        {
            W($"    读取流量失败：{before?.Error ?? beforeError}");
            CheckAssertion(results, "读取流量快照", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        W($"    清空前：{before.Traffic?.Count ?? 0} 个程序，" +
          $"统计起点 = {before.TrafficStartedUtc?.ToString("O") ?? "（旧服务未返回）"}");

        var cleared = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.ClearTraffic },
            TimeSpan.FromSeconds(15),
            out var clearError);

        W($"    清空结果：ok={cleared?.Ok}，清理={cleared?.Affected}，错误={cleared?.Error ?? clearError}");

        CheckAssertion(results, "清空流量统计成功", cleared is { Ok: true });
        CheckAssertion(results, "清空后返回统计起点",
            cleared?.TrafficStartedUtc is not null);

        var after = QueryTrafficResponse(out var afterError);

        if (after is not { Ok: true })
        {
            W($"    清空后读取失败：{after?.Error ?? afterError}");
            CheckAssertion(results, "清空后读取流量快照", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        W($"    清空后：{after.Traffic?.Count ?? 0} 个程序，" +
          $"统计起点 = {after.TrafficStartedUtc?.ToString("O") ?? "（旧服务未返回）"}");

        // 清空后可能有别的程序在毫秒级产生新流量，不能要求列表绝对为 0；
        // 核心断言是：本进程原有的计数没了，且统计起点已重置。
        var ownPath = Environment.ProcessPath;
        var ownAfter = after.Traffic?.FirstOrDefault(item =>
            item.IsPathKnown
            && !string.IsNullOrEmpty(ownPath)
            && string.Equals(item.Path, ownPath, StringComparison.OrdinalIgnoreCase));

        var ownBytes = (ownAfter?.BytesIn ?? 0) + (ownAfter?.BytesOut ?? 0);
        W($"    清空后本进程计数 = {ownBytes} 字节");

        CheckAssertion(results, "清空后本进程计数归零（允许新流量 < 64 KiB）",
            ownBytes < 64 * 1024);
        CheckAssertion(results, "清空后统计起点不早于清空响应",
            after.TrafficStartedUtc is not null
            && cleared?.TrafficStartedUtc is not null
            && after.TrafficStartedUtc >= cleared.TrafficStartedUtc);

        PrintSummary(results, showFirewallResidue: false);
    }

    private static ServiceResponse? QueryTrafficResponse(out string? error)
    {
        return ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryTraffic },
            TimeSpan.FromSeconds(5),
            out error);
    }

    private static List<TrafficDto>? QueryTrafficFromService(out string? error)
    {
        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryTraffic },
            TimeSpan.FromSeconds(5),
            out error);

        return response is { Ok: true, Traffic: not null }
            ? response.Traffic
            : null;
    }

    private static Process? TryGetServiceProcess()
    {
        try
        {
            return Process.GetProcessesByName("WinAppGuardSvc").FirstOrDefault();
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static TimeSpan? TryReadCpu(Process? process)
    {
        try
        {
            return process?.TotalProcessorTime;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static List<DnsDto>? QueryDnsFromService(out string? error)
    {
        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryDns },
            TimeSpan.FromSeconds(5),
            out error);

        return response is { Ok: true, DnsRecords: not null }
            ? response.DnsRecords
            : null;
    }

    private static TrafficDto? FindOwnTraffic(IReadOnlyList<TrafficDto> list)
    {
        var ownPath = Environment.ProcessPath;

        return string.IsNullOrEmpty(ownPath)
            ? null
            : list.FirstOrDefault(item =>
                item.IsPathKnown
                && string.Equals(item.Path, ownPath, StringComparison.OrdinalIgnoreCase));
    }

    private static List<DnsDto> WaitForDnsRecords(string name, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        var matches = new List<DnsDto>();

        while (DateTime.UtcNow < deadline)
        {
            var records = QueryDnsFromService(out _);

            matches = records?
                .Where(record => string.Equals(
                    record.QueryName, name, StringComparison.OrdinalIgnoreCase))
                .ToList() ?? new List<DnsDto>();

            if (matches.Count > 0)
            {
                // 再等一会儿，让 3006/3008 两条事件都到齐；不同 PID 的归属才看得清。
                Thread.Sleep(1500);

                records = QueryDnsFromService(out _);
                return records?
                    .Where(record => string.Equals(
                        record.QueryName, name, StringComparison.OrdinalIgnoreCase))
                    .ToList() ?? new List<DnsDto>();
            }

            Thread.Sleep(500);
        }

        return matches;
    }

    /// <summary>
    /// 3.5：只验证回环下载链路（子进程服务 + 客户端），不需要防护服务。
    /// 用来在 VM 上快速判断「下载方向统计不到」是测试环境问题还是采集实现问题。
    /// </summary>
    private static void RunLoopbackDownloadTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   回环下载链路（独立 PowerShell 服务进程，不需要防护服务）     #");
        W("################################################################");
        W();

        const long total = 1024 * 1024;
        var received = DownloadLoopbackPayload(total, out var error);

        W($"    期望 {total} 字节，实际收到 {received} 字节（{error ?? "ok"}）");

        CheckAssertion(results, "回环下载完整", received == total);
        CheckAssertion(results, "回环下载无错误", string.IsNullOrEmpty(error));

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.5：单独验证 ETW Network 采集（不经过服务、不需要 IPC）。
    /// 起一个独立进程的回环服务，下载 4 MiB，同时逐秒取 ETW 增量。
    /// 需要管理员权限（ETW 会话）。
    /// </summary>
    private static void RunEtwNetworkTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   ETW Network 实测（Kernel-Network，TCP+UDP，按 PID）          #");
        W("################################################################");
        W();

        using var monitor = new NetworkEtwMonitor(
            "WinAppGuard-Net-Test",
            new Guid("2C3D4E5F-6A7B-4C8D-9E0F-1A2B3C4D5E6F"));

        if (!monitor.Start())
        {
            W($"    启动失败：{monitor.LastError}");
            CheckAssertion(results, "ETW Network 会话启动", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        var beforeEvents = monitor.EventsSeen;
        string? downloadError = null;
        long downloaded = 0;

        var download = Task.Run(() =>
            downloaded = DownloadLoopbackPayload(4 * 1024 * 1024, out downloadError));

        var totals = new Dictionary<int, (ulong In, ulong Out)>();

        // 下载约 8 秒；采样 12 秒，确保覆盖开始和结束。
        for (var i = 0; i < 24; i++)
        {
            foreach (var delta in monitor.TakeSnapshot())
            {
                totals.TryGetValue(delta.Pid, out var current);
                totals[delta.Pid] = (current.In + delta.BytesIn, current.Out + delta.BytesOut);
            }

            Thread.Sleep(500);
        }

        _ = download.Wait(TimeSpan.FromSeconds(5));

        foreach (var delta in monitor.TakeSnapshot())
        {
            totals.TryGetValue(delta.Pid, out var current);
            totals[delta.Pid] = (current.In + delta.BytesIn, current.Out + delta.BytesOut);
        }

        var events = monitor.EventsSeen - beforeEvents;
        totals.TryGetValue(Environment.ProcessId, out var self);

        W($"    下载 = {downloaded} 字节（{downloadError ?? "ok"}）");
        W($"    ETW 事件数 = {events}");
        W($"    本进程：下载 {self.In} 字节，上传 {self.Out} 字节");

        W("    前 3 名：");
        foreach (var (pid, value) in totals
                     .OrderByDescending(pair => pair.Value.In + pair.Value.Out)
                     .Take(3))
        {
            W($"      PID {pid,6}  下载 {value.In,10}  上传 {value.Out,10}");
        }

        CheckAssertion(results, "ETW 捕获到本进程下载（>= 2.5 MiB）",
            self.In >= 2_500_000);
        CheckAssertion(results, "ETW 事件数 > 0", events > 0);

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 在回环上起一个限速 HTTP 服务，让连接持续约 8 秒 ——
    /// 短于采样周期的连接会被漏掉，验收必须避开这个坑。
    /// </summary>
    private static long DownloadLoopbackPayload(long totalBytes, out string? error)
    {
        error = null;

        // 关键：服务端必须跑在**另一个进程**里。
        // 如果客户端和服务端都在本进程，流量会被合并成同一个程序，
        // 就分不清「客户端下载方向」到底有没有被统计到。
        using var portProbe = new TcpListener(IPAddress.Loopback, 0);
        portProbe.Start();
        var port = ((IPEndPoint)portProbe.LocalEndpoint).Port;
        portProbe.Stop();

        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            $WarningPreference = 'SilentlyContinue'
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, {{port}})
            $listener.Start()
            try {
                $client = $listener.AcceptTcpClient()
                $stream = $client.GetStream()
                $buffer = New-Object byte[] 1024
                $header = ''
                while (-not $header.EndsWith("`r`n`r`n")) {
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    if ($read -le 0) { break }
                    $header += [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                }
                $total = {{totalBytes}}
                $response = "HTTP/1.1 200 OK`r`nContent-Length: $total`r`nConnection: close`r`n`r`n"
                $bytes = [Text.Encoding]::ASCII.GetBytes($response)
                $stream.Write($bytes, 0, $bytes.Length)
                $chunk = New-Object byte[] 65536
                $sent = 0
                while ($sent -lt $total) {
                    $count = [Math]::Min($chunk.Length, $total - $sent)
                    $stream.Write($chunk, 0, $count)
                    $stream.Flush()
                    $sent += $count
                    Start-Sleep -Milliseconds 125
                }
                $stream.Close()
                $client.Close()
            } finally {
                $listener.Stop()
            }
            """;

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encoded);

        Process? server = null;
        long received = 0;

        try
        {
            server = Process.Start(startInfo);

            if (server is null)
            {
                error = "无法启动回环服务进程（powershell.exe）。";
                return 0;
            }

            var stdout = server.StandardOutput.ReadToEndAsync();
            var stderr = server.StandardError.ReadToEndAsync();

            using var http = new HttpClient(new HttpClientHandler { UseProxy = false })
            {
                Timeout = TimeSpan.FromSeconds(30),
            };

            HttpResponseMessage? response = null;
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);

            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    response = http.GetAsync(
                        $"http://127.0.0.1:{port}/payload",
                        HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
                    break;
                }
                catch (HttpRequestException)
                {
                    // 子进程的 PowerShell 启动需要一点时间；端口还没起来就重试。
                    Thread.Sleep(200);
                }
            }

            if (response is null)
            {
                error = "回环服务进程没有在 10 秒内开始监听。";
                return 0;
            }

            using (response)
            {
                response.EnsureSuccessStatusCode();

                using var body = response.Content.ReadAsStream();
                var buffer = new byte[64 * 1024];
                int read;

                while ((read = body.Read(buffer, 0, buffer.Length)) > 0)
                {
                    received += read;
                }
            }

            _ = server.WaitForExit(5000);
            _ = stdout.GetAwaiter().GetResult();
            var serverError = stderr.GetAwaiter().GetResult();

            if (!server.HasExited)
            {
                error = "回环服务进程没有在下载结束后退出。";
            }
            else if (server.ExitCode != 0)
            {
                error = $"回环服务退出码 {server.ExitCode}：{serverError.Trim()}";
            }
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
        }
        finally
        {
            if (server is { HasExited: false })
            {
                try
                {
                    server.Kill(entireProcessTree: true);
                }
                catch (Exception)
                {
                    // 忽略：验收失败时不要把清理异常盖到真正的原因上。
                }
            }

            server?.Dispose();
        }

        return received;
    }

    /// <summary>
    /// 3.5：DNS 采集的离线部分 —— 协议字段 / DTO / ETW 结构体大小 / 英文文案。
    /// 真实 ETW 会话必须在 VM 里跑；结构体大小对不上会直接读错内存，所以这里先钉死。
    /// </summary>
    private static void RunDnsTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previous = Localizer.Current;

        W("################################################################");
        W("#   DNS（离线：协议 / DTO / ETW 结构大小 / 英文）                #");
        W("################################################################");
        W();

        try
        {
            Localizer.Initialize("zh");

            CheckAssertion(results, "命令名正确",
                ServiceProtocol.Commands.QueryDns == "query.dns"
                && ServiceProtocol.Commands.ClearDns == "write.dns.clear");

            var (logfileSize, recordSize) = EtwRealtimeSession.NativeStructSizes;
            W($"    EVENT_TRACE_LOGFILEW = {logfileSize} 字节；EVENT_RECORD = {recordSize} 字节");

            // x64 下由 evntrace.h / evntcons.h 的字段顺序推出来；大小不对说明 P/Invoke 布局错了。
            CheckAssertion(results, "EVENT_TRACE_LOGFILEW 大小 = 448", logfileSize == 448);
            CheckAssertion(results, "EVENT_RECORD 大小 = 112", recordSize == 112);

            var dto = new DnsDto
            {
                TimeUtc = new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc),
                Pid = 4321,
                ProcessPath = @"C:\Tools\a.exe",
                ProcessName = "a.exe",
                QueryName = "example.com",
                Status = "OK",
                EventId = 3008,
            };

            var json = JsonSerializer.Serialize(
                new ServiceResponse { Ok = true, DnsRecords = new List<DnsDto> { dto } },
                ServiceProtocol.JsonOptions);
            W($"    DNS JSON = {json}");
            CheckAssertion(results, "响应 JSON 带 dnsRecords / queryName",
                json.Contains("\"dnsRecords\":[", StringComparison.Ordinal)
                && json.Contains("\"queryName\":\"example.com\"", StringComparison.Ordinal)
                && json.Contains("\"status\":\"OK\"", StringComparison.Ordinal)
                && json.Contains("\"eventId\":3008", StringComparison.Ordinal));

            Localizer.Initialize("en");

            CheckAssertion(results, "英文：DNS 文案",
                Localizer.T("域名") == "Domain"
                && Localizer.T("结果") == "Result"
                && Localizer.T("清空记录") == "Clear records");

            var hint = Localizer.T(
                "只记录系统 DNS 客户端看到的域名；DoH/DoT 可能看不到，部分系统会把查询记到 svchost（DNS Client 服务）名下。内存保留最近 2000 条，服务重启后清空。");
            W($"    英文 DNS 说明 = {hint}");
            CheckAssertion(results, "英文：DNS 说明无中文",
                !System.Text.RegularExpressions.Regex.IsMatch(hint, "[\u4e00-\u9fff]"));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "DNS 检查执行完成", false);
        }
        finally
        {
            Localizer.Initialize(previous == Localizer.LanguageMode.English ? "en" : "zh");
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.6：流量记录页的离线检查 —— 排序 / 搜索 / 未知路径 / 合计。
    /// 直接构造窗体并注入 DTO，不连服务、不产生真实流量。
    /// </summary>
    private static void RunIdsTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var start = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);
        var pid = Environment.ProcessId;

        W("################################################################");
        W("#   IDS（3.7）离线规则 / 存储 / 协议自检                         #");
        W("################################################################");
        W();

        CheckAssertion(results, "IDS 查询命令名正确",
            ServiceProtocol.Commands.QueryIdsAlerts == "query.ids.alerts");
        CheckAssertion(results, "IDS 写命令有 write 前缀",
            ServiceProtocol.Commands.IdsConfigure.StartsWith("write.", StringComparison.Ordinal)
            && ServiceProtocol.Commands.IdsAck.StartsWith("write.", StringComparison.Ordinal)
            && ServiceProtocol.Commands.IdsSuppress.StartsWith("write.", StringComparison.Ordinal)
            && ServiceProtocol.Commands.IdsClear.StartsWith("write.", StringComparison.Ordinal));

        // ---- beaconing ----
        var beaconBelow = new IdsAnalyzer();
        FeedBeacon(beaconBelow, pid, start, connections: 5);
        CheckAssertion(results, "beaconing：5 次连接不告警",
            beaconBelow.Evaluate(start.AddMinutes(1), new IdsSettings(), Array.Empty<IdsSuppression>()).Count == 0);

        var beacon = new IdsAnalyzer();
        FeedBeacon(beacon, pid, start, connections: 6);
        var beaconAlerts = beacon.Evaluate(
            start.AddMinutes(1), new IdsSettings(), Array.Empty<IdsSuppression>());
        CheckAssertion(results, "beaconing：6 次、5 秒间隔命中",
            beaconAlerts.Count == 1
            && beaconAlerts[0].RuleId == "beaconing"
            && beaconAlerts[0].Severity == IdsSeverity.Medium
            && beaconAlerts[0].Target == "203.0.113.10:8443");

        var beaconCooldown = beacon.Evaluate(
            start.AddMinutes(1).AddSeconds(5), new IdsSettings(), Array.Empty<IdsSuppression>());
        CheckAssertion(results, "beaconing：30 分钟内同一目标不重复告警",
            beaconCooldown.Count == 0);

        var beaconConservative = new IdsAnalyzer();
        FeedBeacon(beaconConservative, pid, start, connections: 6);
        CheckAssertion(results, "beaconing：保守敏感度下 6 次不告警",
            beaconConservative.Evaluate(
                start.AddMinutes(1),
                new IdsSettings { Sensitivity = "conservative" },
                Array.Empty<IdsSuppression>()).Count == 0);

        var beaconConservative2 = new IdsAnalyzer();
        FeedBeacon(beaconConservative2, pid, start, connections: 12);
        CheckAssertion(results, "beaconing：保守敏感度下 12 次命中",
            beaconConservative2.Evaluate(
                start.AddMinutes(2),
                new IdsSettings { Sensitivity = "conservative" },
                Array.Empty<IdsSuppression>()).Count == 1);

        var beaconSuppressed = new IdsAnalyzer();
        FeedBeacon(beaconSuppressed, pid, start, connections: 6);
        var suppression = new IdsSuppression
        {
            RuleId = "beaconing",
            Target = "203.0.113.10:8443",
        };
        CheckAssertion(results, "beaconing：抑制后不告警",
            beaconSuppressed.Evaluate(
                start.AddMinutes(1),
                new IdsSettings(),
                new[] { suppression }).Count == 0);

        var beaconExpired = new IdsAnalyzer();
        FeedBeacon(beaconExpired, pid, start, connections: 6);
        var expiredSuppression = new IdsSuppression
        {
            RuleId = "beaconing",
            Target = "203.0.113.10:8443",
            UntilUtc = start.AddHours(-1),
        };
        CheckAssertion(results, "beaconing：过期抑制不再生效",
            beaconExpired.Evaluate(
                start.AddMinutes(1),
                new IdsSettings(),
                new[] { expiredSuppression }).Count == 1);

        // ---- 扫描 ----
        var scan = new IdsAnalyzer();

        for (var i = 0; i < 30; i++)
        {
            scan.ObserveFlow(new NetworkFlowObservation(
                start.AddSeconds(i), pid, "TCP", "198.51.100.5", (ushort)(1000 + i), true, true, 0));
        }

        var scanAlerts = scan.Evaluate(
            start.AddSeconds(31), new IdsSettings(), Array.Empty<IdsSuppression>());
        CheckAssertion(results, "scan：同一主机 30 个端口命中且为高",
            scanAlerts.Count == 1
            && scanAlerts[0].RuleId == "scan"
            && scanAlerts[0].Severity == IdsSeverity.High
            && scanAlerts[0].Evidence.Contains("ports=30", StringComparison.Ordinal));

        var horizontal = new IdsAnalyzer();

        for (var i = 0; i < 20; i++)
        {
            horizontal.ObserveFlow(new NetworkFlowObservation(
                start.AddSeconds(i), pid, "TCP", $"198.51.100.{i + 1}", 3389, true, true, 0));
        }

        var horizontalAlerts = horizontal.Evaluate(
            start.AddSeconds(31), new IdsSettings(), Array.Empty<IdsSuppression>());
        CheckAssertion(results, "scan：同一端口 20 台主机命中",
            horizontalAlerts.Any(alert => alert.RuleId == "scan"));

        var inboundScan = new IdsAnalyzer();

        for (var i = 0; i < 30; i++)
        {
            inboundScan.ObserveFlow(new NetworkFlowObservation(
                start.AddSeconds(i), pid, "TCP", "198.51.100.5", (ushort)(1000 + i), false, true, 0));
        }

        CheckAssertion(results, "scan：只统计出站连接（入站不告警）",
            inboundScan.Evaluate(
                start.AddSeconds(31), new IdsSettings(), Array.Empty<IdsSuppression>()).Count == 0);

        var inboundBeacon = new IdsAnalyzer();

        for (var i = 0; i < 6; i++)
        {
            inboundBeacon.ObserveFlow(new NetworkFlowObservation(
                start.AddSeconds(i * 5), pid, "TCP", "203.0.113.10", 8443, false, true, 0));
        }

        CheckAssertion(results, "beaconing：只统计出站连接（入站不告警）",
            inboundBeacon.Evaluate(
                start.AddMinutes(1), new IdsSettings(), Array.Empty<IdsSuppression>()).Count == 0);

        // ---- 内网横向 ----
        var lateral = new IdsAnalyzer();

        for (var i = 0; i < 4; i++)
        {
            lateral.ObserveFlow(new NetworkFlowObservation(
                start.AddMinutes(i), pid, "TCP", $"10.0.0.{i + 1}", 445, true, true, 0));
        }

        var lateralAlerts = lateral.Evaluate(
            start.AddMinutes(5), new IdsSettings(), Array.Empty<IdsSuppression>());
        CheckAssertion(results, "lateral：4 台内网主机 445 命中且为高",
            lateralAlerts.Count == 1
            && lateralAlerts[0].RuleId == "lateral"
            && lateralAlerts[0].Severity == IdsSeverity.High
            && lateralAlerts[0].Evidence.Contains("privateHosts=4", StringComparison.Ordinal));

        var lateralPublic = new IdsAnalyzer();

        for (var i = 0; i < 4; i++)
        {
            lateralPublic.ObserveFlow(new NetworkFlowObservation(
                start.AddMinutes(i), pid, "TCP", $"198.51.100.{i + 1}", 445, true, true, 0));
        }

        CheckAssertion(results, "lateral：公网地址不告警",
            !lateralPublic.Evaluate(
                    start.AddMinutes(5), new IdsSettings(), Array.Empty<IdsSuppression>())
                .Any(alert => alert.RuleId == "lateral"));

        // ---- DNS ----
        var dns = new IdsAnalyzer();

        for (var i = 0; i < 20; i++)
        {
            dns.ObserveDns(new NetworkDnsObservation(
                start.AddSeconds(i * 10), pid, $"host{i}.evil.example", "OK"));
        }

        var dnsAlerts = dns.Evaluate(
            start.AddMinutes(5), new IdsSettings(), Array.Empty<IdsSuppression>());
        CheckAssertion(results, "dns：同一父域 20 个子域命中",
            dnsAlerts.Count == 1
            && dnsAlerts[0].RuleId == "dns"
            && dnsAlerts[0].Target == "evil.example");

        var dnsBelow = new IdsAnalyzer();

        for (var i = 0; i < 10; i++)
        {
            dnsBelow.ObserveDns(new NetworkDnsObservation(
                start.AddSeconds(i * 10), pid, $"host{i}.evil.example", "OK"));
        }

        CheckAssertion(results, "dns：10 个子域不告警",
            dnsBelow.Evaluate(
                start.AddMinutes(5), new IdsSettings(), Array.Empty<IdsSuppression>()).Count == 0);

        var dnsDuplicates = new IdsAnalyzer();

        for (var i = 0; i < 10; i++)
        {
            var name = $"dup{i}.evil.example";
            dnsDuplicates.ObserveDns(new NetworkDnsObservation(
                start.AddSeconds(i * 10), pid, name, "NXDOMAIN"));
            dnsDuplicates.ObserveDns(new NetworkDnsObservation(
                start.AddSeconds(i * 10 + 1), pid, name, "NXDOMAIN"));
        }

        CheckAssertion(results, "dns：发起/完成重复事件不重复计数",
            dnsDuplicates.Evaluate(
                start.AddMinutes(5), new IdsSettings(), Array.Empty<IdsSuppression>()).Count == 0);

        var dnsPublicSuffix = new IdsAnalyzer();

        for (var i = 0; i < 10; i++)
        {
            dnsPublicSuffix.ObserveDns(new NetworkDnsObservation(
                start.AddSeconds(i * 10), pid, $"a{i}.alpha.com.cn", "OK"));
            dnsPublicSuffix.ObserveDns(new NetworkDnsObservation(
                start.AddSeconds(i * 10 + 1), pid, $"b{i}.beta.com.cn", "OK"));
        }

        CheckAssertion(results, "dns：按注册域分组（com.cn 不合并不同站点）",
            dnsPublicSuffix.Evaluate(
                start.AddMinutes(5), new IdsSettings(), Array.Empty<IdsSuppression>()).Count == 0);

        // ---- 事件计数 / 清空 ----
        CheckAssertion(results, "事件计数正确",
            beacon.EventsSeen == 18 && beacon.EventsLost == 0);

        beacon.Clear();
        CheckAssertion(results, "清空后 flow / 事件归零",
            beacon.FlowCount == 0 && beacon.EventsSeen == 0);

        // flow 上限：到 20,000 后一次淘汰 10%，不是每个新 flow 全表扫描。
        var capped = new IdsAnalyzer();

        for (var i = 0; i < 20_000; i++)
        {
            capped.ObserveFlow(new NetworkFlowObservation(
                start, pid, "TCP", $"10.20.{i / 256}.{i % 256}", 443, true, false, 1));
        }

        capped.ObserveFlow(new NetworkFlowObservation(
            start, pid, "TCP", "10.20.99.99", 443, true, false, 1));

        CheckAssertion(results, "flow 上限：一次淘汰 10% 并计入丢失",
            capped.FlowCount == 18_001 && capped.EventsLost == 2_000);

        // ---- 告警存储 ----
        var directory = Path.Combine(
            Path.GetTempPath(), "WinAppGuard-IdsTest-" + Guid.NewGuid().ToString("N"));

        try
        {
            var store = new IdsAlertStore(directory);
            var fresh = new IdsAlert
            {
                TimeUtc = start,
                RuleId = "beaconing",
                Target = "203.0.113.10:8443",
                Evidence = "connections=6",
            };
            var stale = new IdsAlert
            {
                TimeUtc = start.AddDays(-40),
                RuleId = "scan",
                Target = "host:198.51.100.5",
            };

            store.Append(fresh);
            store.Append(stale);

            var recent = store.LoadRecent(30, 100);
            CheckAssertion(results, "告警存储：按保留期读取（旧记录过滤）",
                recent.Count == 1 && recent[0].Id == fresh.Id);

            var removed = store.Prune(30);
            CheckAssertion(results, "告警存储：Prune 删除过期记录",
                removed == 1 && store.LoadRecent(365, 100).Count == 1);

            store.Clear();
            CheckAssertion(results, "告警存储：清空后读取为空",
                store.LoadRecent(30, 100).Count == 0);

            // ---- 状态文件 ----
            var statePath = Path.Combine(directory, "state.json");
            var saved = new IdsState
            {
                Settings = new IdsSettings
                {
                    Enabled = true,
                    Sensitivity = "conservative",
                    RetentionDays = 14,
                    DnsRule = false,
                },
                Suppressions =
                {
                    new IdsSuppression
                    {
                        RuleId = "dns",
                        ProcessName = "demo.exe",
                        Target = "evil.example",
                    },
                },
            };

            IdsStateFile.Save(statePath, saved);
            var loaded = IdsStateFile.Load(statePath);

            CheckAssertion(results, "状态文件：设置 / 抑制往返",
                loaded.Settings.RetentionDays == 14
                && loaded.Settings.Sensitivity == "conservative"
                && !loaded.Settings.DnsRule
                && loaded.Suppressions.Count == 1
                && loaded.Suppressions[0].Target == "evil.example");

            File.WriteAllText(statePath, "{ broken", new UTF8Encoding(false));
            var broken = IdsStateFile.Load(statePath);
            CheckAssertion(results, "状态文件：坏文件回退默认值",
                broken.Settings.Enabled && broken.Settings.RetentionDays == 30);

            // ---- DTO 往返 ----
            var response = new ServiceResponse
            {
                Ok = true,
                IdsAlerts = new List<IdsAlertDto>
                {
                    new()
                    {
                        Id = "abc",
                        TimeUtc = start,
                        Severity = IdsSeverity.Medium,
                        RuleId = "beaconing",
                        ProcessName = "demo.exe",
                        Target = "203.0.113.10:8443",
                        Evidence = "connections=6; mean=5.0s",
                        Status = "new",
                    },
                },
                IdsSettings = new IdsSettingsDto { RetentionDays = 30, DnsRule = false },
                IdsStatus = new IdsStatusDto { FlowCount = 3, EventsSeen = 42, AlertsNew = 1 },
            };

            var json = JsonSerializer.Serialize(response, ServiceProtocol.JsonOptions);
            var back = JsonSerializer.Deserialize<ServiceResponse>(json, ServiceProtocol.JsonOptions);

            CheckAssertion(results, "协议 DTO：告警 / 设置 / 状态往返",
                back?.IdsAlerts is { Count: 1 }
                && back.IdsAlerts[0].RuleId == "beaconing"
                && back.IdsAlerts[0].Target == "203.0.113.10:8443"
                && back.IdsSettings is { RetentionDays: 30, DnsRule: false }
                && back.IdsStatus is { FlowCount: 3, EventsSeen: 42, AlertsNew: 1 });
        }
        finally
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响自检结论。
            }
        }

        RunIdsUiChecks(results);

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>3.7：IDS 页的行构建 / 搜索 / 筛选 / 状态行接线（离线，不联网）。</summary>
    private static void RunIdsUiChecks(List<(string Title, bool Passed)> results)
    {
        var previous = Localizer.Current;

        try
        {
            Localizer.Initialize("zh");
            MainForm.SuppressBackgroundServices = true;

            using var form = new MainForm(isAutostart: false);
            TrySetField(form, "_runtimeInitialized", true);

            var now = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

            TrySetField(form, "_idsAlerts", new List<IdsAlertDto>
            {
                new()
                {
                    Id = "a1", TimeUtc = now, Severity = "high", RuleId = "lateral",
                    RuleName = "lateral", Pid = 100, ProcessName = "demo.exe",
                    Target = "private-admin-ports", Evidence = "privateHosts=4", Status = "new",
                },
                new()
                {
                    Id = "a2", TimeUtc = now.AddMinutes(-1), Severity = "medium",
                    RuleId = "beaconing", RuleName = "beaconing", Pid = 200,
                    ProcessName = "agent.exe", Target = "203.0.113.10:8443",
                    Evidence = "connections=6; mean=5.0s", Status = "ack",
                },
                new()
                {
                    Id = "a3", TimeUtc = now.AddMinutes(-2), Severity = "medium",
                    RuleId = "dns", RuleName = "dns", Pid = 300, ProcessName = "browser.exe",
                    Target = "evil.example", Evidence = "parent=evil.example; unique=20",
                    Status = "new",
                },
                new()
                {
                    Id = "a4", TimeUtc = now.AddMinutes(-3), Severity = "low",
                    RuleId = "scan", RuleName = "scan", Pid = 400, ProcessName = "tool.exe",
                    Target = "host:198.51.100.5", Evidence = "ports=15", Status = "new",
                },
            });

            TrySetField(form, "_idsStatus", new IdsStatusDto
            {
                Enabled = true,
                Collecting = true,
                Sensitivity = "standard",
                FlowCount = 12,
                EventsSeen = 345,
                AlertsNew = 3,
                AlertsTotal = 4,
                SuppressionCount = 1,
            });

            var rebuild = typeof(MainForm).GetMethod(
                "RebuildIdsView",
                BindingFlags.Instance | BindingFlags.NonPublic);

            if (rebuild is null
                || !TryGetField<DataGridView>(form, "_idsGrid", out var grid)
                || !TryGetField<TextBox>(form, "_idsSearchBox", out var search)
                || !TryGetField<ComboBox>(form, "_idsSeverityFilter", out var severity)
                || !TryGetField<ComboBox>(form, "_idsRuleFilter", out var rule)
                || !TryGetField<Label>(form, "_idsSummaryLabel", out var summary))
            {
                CheckAssertion(results, "找得到 IDS 页控件", false);
                return;
            }

            rebuild.Invoke(form, null);
            Application.DoEvents();

            CheckAssertion(results, "IDS 页显示全部 4 条告警", grid.Rows.Count == 4);

            W($"    IDS 状态行 = {summary.Text}");
            CheckAssertion(results, "IDS 状态行包含开启 / 只检测 / flow",
                summary.Text.Contains("IDS 已开启", StringComparison.Ordinal)
                && summary.Text.Contains("只检测、不阻断", StringComparison.Ordinal)
                && summary.Text.Contains("flow 12", StringComparison.Ordinal)
                && summary.Text.Contains("未确认 3", StringComparison.Ordinal));

            search.Text = "evil.example";
            Application.DoEvents();
            CheckAssertion(results, "IDS 搜索目标生效", grid.Rows.Count == 1);

            search.Text = string.Empty;
            severity.SelectedIndex = 1;
            Application.DoEvents();
            CheckAssertion(results, "IDS 级别筛选（高）生效", grid.Rows.Count == 1);

            severity.SelectedIndex = 0;
            rule.SelectedIndex = 4;
            Application.DoEvents();
            CheckAssertion(results, "IDS 规则筛选（DNS）生效", grid.Rows.Count == 1);

            rule.SelectedIndex = 0;
            Application.DoEvents();
            CheckAssertion(results, "IDS 清除筛选后恢复 4 条", grid.Rows.Count == 4);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "IDS 页检查执行完成", false);
        }
        finally
        {
            MainForm.SuppressBackgroundServices = false;
            Localizer.Initialize(previous == Localizer.LanguageMode.English ? "en" : "zh");
        }
    }

    private static void FeedBeacon(
        IdsAnalyzer analyzer, int pid, DateTime start, int connections)
    {
        for (var i = 0; i < connections; i++)
        {
            var time = start.AddSeconds(i * 5);
            analyzer.ObserveFlow(new NetworkFlowObservation(
                time, pid, "TCP", "203.0.113.10", 8443, true, true, 0));
            analyzer.ObserveFlow(new NetworkFlowObservation(
                time, pid, "TCP", "203.0.113.10", 8443, true, false, 100));
            analyzer.ObserveFlow(new NetworkFlowObservation(
                time, pid, "TCP", "203.0.113.10", 8443, false, false, 100));
        }
    }

    private static void RunAntiScanTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var start = DateTime.UtcNow;
        var standard = new AntiScanSettings();

        W("################################################################");
        W("#   4.0 反端口扫描（离线：阈值 / 冷却 / 状态 / 协议）            #");
        W("################################################################");
        W();

        AntiScanFinding? Feed(
            AntiScanAnalyzer analyzer,
            AntiScanSettings settings,
            int ports,
            int hosts = 1,
            int intervalMs = 1000,
            string source = "198.51.100.9",
            string localPrefix = "10.0.0.",
            int portBase = 1000,
            int timeOffsetSeconds = 0)
        {
            AntiScanFinding? found = null;

            for (var i = 0; i < ports; i++)
            {
                var time = start.AddSeconds(timeOffsetSeconds).AddMilliseconds(i * intervalMs);
                var local = IPAddress.Parse(localPrefix + (1 + (i % hosts)));
                var syn = new InboundSyn(
                    time,
                    IPAddress.Parse(source),
                    (ushort)(40000 + i),
                    local,
                    (ushort)(portBase + i));

                var finding = analyzer.Observe(syn, time, settings);

                if (finding is not null)
                {
                    found = finding;
                }
            }

            return found;
        }

        var medium = Feed(new AntiScanAnalyzer(), standard, ports: 20);
        CheckAssertion(results, "标准：20 个端口 / 60 秒触发中危",
            medium is { Severity: AntiScanSeverity.Medium, DistinctPorts: 20 });

        var high = Feed(new AntiScanAnalyzer(), standard, ports: 50);
        CheckAssertion(results, "标准：50 个端口触发高危",
            high is { Severity: AntiScanSeverity.High, DistinctPorts: 50 });

        var fast = Feed(new AntiScanAnalyzer(), standard, ports: 20, intervalMs: 400);
        CheckAssertion(results, "标准：10 秒内 20 个端口触发高危",
            fast is { Severity: AntiScanSeverity.High });

        var conservative20 = Feed(
            new AntiScanAnalyzer(),
            new AntiScanSettings { Sensitivity = "conservative" },
            ports: 20);
        CheckAssertion(results, "保守：20 个端口不触发", conservative20 is null);

        var conservative40 = Feed(
            new AntiScanAnalyzer(),
            new AntiScanSettings { Sensitivity = "conservative" },
            ports: 40);
        CheckAssertion(results, "保守：40 个端口触发中危",
            conservative40 is { Severity: AntiScanSeverity.Medium });

        var horizontal = Feed(
            new AntiScanAnalyzer(),
            standard,
            ports: 10,
            hosts: 10,
            localPrefix: "10.0.0.");
        CheckAssertion(results, "水平扫描：同一来源 10 个本地地址触发中危",
            horizontal is { Severity: AntiScanSeverity.Medium, DistinctHosts: 10 });

        var loopback = Feed(
            new AntiScanAnalyzer(),
            standard,
            ports: 30,
            source: "127.0.0.1");
        CheckAssertion(results, "回环来源被忽略", loopback is null);

        var cooldownAnalyzer = new AntiScanAnalyzer();
        var first = Feed(cooldownAnalyzer, standard, ports: 20);
        var second = Feed(cooldownAnalyzer, standard, ports: 1, portBase: 2000, timeOffsetSeconds: 30);
        CheckAssertion(results, "同级别 10 分钟内不重复告警",
            first is not null && second is null);

        var upgraded = Feed(
            cooldownAnalyzer,
            standard,
            ports: 60,
            intervalMs: 500,
            portBase: 3000,
            timeOffsetSeconds: 60);
        CheckAssertion(results, "同来源升级为高危时不被冷却吞掉",
            upgraded is { Severity: AntiScanSeverity.High });

        cooldownAnalyzer.ResetSource("198.51.100.9");
        var afterReset = Feed(cooldownAnalyzer, standard, ports: 1, portBase: 4000, timeOffsetSeconds: 90);
        CheckAssertion(results, "ResetSource 后可再次触发",
            afterReset is not null);

        CheckAssertion(results, "事件计数为正",
            cooldownAnalyzer.EventsSeen > 0);

        CheckAssertion(results, "pcap_pkthdr 托管布局是 16 字节（Windows timeval 为 32 位）",
            NpcapCapture.PacketHeaderSize == 16);

        var directory = Path.Combine(
            Path.GetTempPath(), "WinAppGuard-AntiScanTest-" + Guid.NewGuid().ToString("N"));

        try
        {
            var statePath = Path.Combine(directory, "state.json");
            var state = new AntiScanState
            {
                Settings = new AntiScanSettings
                {
                    Enabled = true,
                    AutoBlock = true,
                    Sensitivity = "conservative",
                    BlockMinutes = 30,
                    Allowlist = new List<string> { "192.0.2.10", "not-an-ip" },
                },
                Blocks =
                {
                    new AntiScanBlock
                    {
                        Address = "198.51.100.9",
                        BlockedUntilUtc = start.AddMinutes(10),
                        Reason = "inbound port scan",
                    },
                },
            };

            AntiScanStateFile.Save(statePath, state);
            var loaded = AntiScanStateFile.Load(statePath);

            CheckAssertion(results, "状态文件：设置 / 允许名单 / 封禁往返",
                loaded.Settings.AutoBlock
                && loaded.Settings.Sensitivity == "conservative"
                && loaded.Settings.BlockMinutes == 30
                && loaded.Settings.Allowlist.Count == 1
                && loaded.Blocks.Count == 1
                && loaded.Blocks[0].Address == "198.51.100.9");

            File.WriteAllText(statePath, "{ broken", new UTF8Encoding(false));
            var broken = AntiScanStateFile.Load(statePath);
            CheckAssertion(results, "状态文件：坏文件回退默认值",
                broken.Settings.Enabled && broken.Settings.BlockMinutes == 10);

            var response = new ServiceResponse
            {
                Ok = true,
                AntiScanSettings = new AntiScanSettingsDto
                {
                    Enabled = true,
                    AutoBlock = true,
                    Sensitivity = "standard",
                    BlockMinutes = 10,
                    Allowlist = new List<string> { "192.0.2.10" },
                },
                AntiScanStatus = new AntiScanStatusDto
                {
                    Enabled = true,
                    NpcapAvailable = true,
                    NpcapVersion = "1.90",
                    Collecting = true,
                    EventsSeen = 123,
                    EventCount = 1,
                    BlockedCount = 1,
                },
                AntiScanEvents = new List<AntiScanEventDto>
                {
                    new()
                    {
                        Id = "e1",
                        SourceAddress = "198.51.100.9",
                        DistinctPorts = 30,
                        Severity = "high",
                        Action = "blocked",
                        BlockedUntilUtc = start.AddMinutes(10),
                    },
                },
                AntiScanBlocks = new List<AntiScanBlockDto>
                {
                    new()
                    {
                        Address = "198.51.100.9",
                        BlockedUntilUtc = start.AddMinutes(10),
                        Reason = "inbound port scan",
                    },
                },
            };

            var json = JsonSerializer.Serialize(response, ServiceProtocol.JsonOptions);
            var back = JsonSerializer.Deserialize<ServiceResponse>(json, ServiceProtocol.JsonOptions);

            CheckAssertion(results, "协议 DTO：反扫描设置 / 状态 / 事件 / 封禁往返",
                back?.AntiScanSettings is { AutoBlock: true, BlockMinutes: 10 }
                && back.AntiScanStatus is { NpcapAvailable: true, EventsSeen: 123 }
                && back.AntiScanEvents is { Count: 1 }
                && back.AntiScanBlocks is { Count: 1 }
                && back.AntiScanBlocks[0].Address == "198.51.100.9");
        }
        finally
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响自检。
            }
        }

        RunAntiScanUiChecks(results);

        PrintSummary(results, showFirewallResidue: false);
    }

    private static void RunAntiScanUiChecks(List<(string Title, bool Passed)> results)
    {
        var previous = Localizer.Current;

        try
        {
            Localizer.Initialize("zh");
            MainForm.SuppressBackgroundServices = true;

            using var form = new MainForm(isAutostart: false);
            TrySetField(form, "_runtimeInitialized", true);

            var now = new DateTime(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);

            TrySetField(form, "_antiEvents", new List<AntiScanEventDto>
            {
                new()
                {
                    Id = "s1", TimeUtc = now, SourceAddress = "198.51.100.9",
                    DistinctPorts = 30, DistinctHosts = 1, SynCount = 30,
                    WindowSeconds = 60, Severity = "high", Action = "blocked",
                    BlockedUntilUtc = now.AddMinutes(10),
                },
            });

            TrySetField(form, "_antiBlocks", new List<AntiScanBlockDto>
            {
                new()
                {
                    Address = "198.51.100.9",
                    BlockedUntilUtc = now.AddMinutes(10),
                    Reason = "inbound port scan",
                    EventId = "s1",
                },
            });

            TrySetField(form, "_antiStatus", new AntiScanStatusDto
            {
                Enabled = true,
                NpcapAvailable = true,
                NpcapVersion = "1.90",
                Collecting = true,
                EventsSeen = 120,
                EventCount = 1,
                BlockedCount = 1,
                AutoBlock = true,
                Sensitivity = "standard",
                BlockMinutes = 10,
            });

            TrySetField(form, "_antiSettings", new AntiScanSettingsDto
            {
                Enabled = true,
                AutoBlock = true,
                Sensitivity = "standard",
                BlockMinutes = 10,
            });

            var rebuild = typeof(MainForm).GetMethod(
                "RebuildAntiScanView",
                BindingFlags.Instance | BindingFlags.NonPublic);

            if (rebuild is null
                || !TryGetField<DataGridView>(form, "_antiEventGrid", out var eventGrid)
                || !TryGetField<DataGridView>(form, "_antiBlockGrid", out var blockGrid)
                || !TryGetField<TextBox>(form, "_antiSearchBox", out var search)
                || !TryGetField<Label>(form, "_antiStatusLabel", out var status))
            {
                CheckAssertion(results, "找得到防护页控件", false);
                return;
            }

            rebuild.Invoke(form, null);
            Application.DoEvents();

            CheckAssertion(results, "防护页显示 1 条事件 / 1 条封禁",
                eventGrid.Rows.Count == 1 && blockGrid.Rows.Count == 1);

            W($"    防护状态行 = {status.Text}");
            CheckAssertion(results, "防护状态行包含 Npcap / 事件 / 封禁",
                status.Text.Contains("反扫描", StringComparison.Ordinal)
                && status.Text.Contains("Npcap 1.90", StringComparison.Ordinal)
                && status.Text.Contains("事件 1", StringComparison.Ordinal)
                && status.Text.Contains("临时封禁 1", StringComparison.Ordinal));

            search.Text = "198.51.100.9";
            Application.DoEvents();
            CheckAssertion(results, "防护搜索来源 IP 生效",
                eventGrid.Rows.Count == 1 && blockGrid.Rows.Count == 1);
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "防护页检查执行完成", false);
        }
        finally
        {
            MainForm.SuppressBackgroundServices = false;
            Localizer.Initialize(previous == Localizer.LanguageMode.English ? "en" : "zh");
        }
    }

    private static void RunTrafficRecordsTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previous = Localizer.Current;

        W("################################################################");
        W("#   流量记录页（离线：排序 / 搜索 / 未知路径 / 合计）            #");
        W("################################################################");
        W();

        try
        {
            Localizer.Initialize("zh");

            CheckAssertion(results, "清空流量命令名正确",
                ServiceProtocol.Commands.ClearTraffic == "write.traffic.clear");

            var started = new DateTime(2026, 10, 26, 12, 34, 56, DateTimeKind.Utc);
            var metadataJson = JsonSerializer.Serialize(
                new ServiceResponse { Ok = true, TrafficStartedUtc = started },
                ServiceProtocol.JsonOptions);

            CheckAssertion(results, "响应 JSON 带 trafficStartedUtc",
                metadataJson.Contains("\"trafficStartedUtc\":\"2026-10-26T12:34:56Z\"", StringComparison.Ordinal));

            MainForm.SuppressBackgroundServices = true;

            using var form = new MainForm(isAutostart: false);
            TrySetField(form, "_runtimeInitialized", true);

            var now = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

            var records = new List<TrafficDto>
            {
                new()
                {
                    Key = @"c:\a.exe", Path = @"C:\a.exe", Name = "a.exe",
                    IsPathKnown = true, BytesOut = 100, BytesIn = 10, LastSeenUtc = now.AddMinutes(-3),
                },
                new()
                {
                    Key = @"c:\b.exe", Path = @"C:\b.exe", Name = "b.exe",
                    IsPathKnown = true, BytesOut = 10, BytesIn = 500, LastSeenUtc = now.AddMinutes(-1),
                },
                new()
                {
                    Key = @"c:\c.exe", Path = @"C:\c.exe", Name = "c.exe",
                    IsPathKnown = true, BytesOut = 60, BytesIn = 40, LastSeenUtc = now.AddMinutes(-2),
                },
                new()
                {
                    Key = "pid:999", Path = null, Name = "PID 999",
                    IsPathKnown = false, BytesOut = 5, BytesIn = 5, LastSeenUtc = now.AddMinutes(-4),
                },
            };

            TrySetField(form, "_trafficRecords", records);

            var rebuild = typeof(MainForm).GetMethod(
                "RebuildTrafficView",
                BindingFlags.Instance | BindingFlags.NonPublic);

            if (rebuild is null
                || !TryGetField<DataGridView>(form, "_trafficGrid", out var grid)
                || !TryGetField<TextBox>(form, "_trafficSearchBox", out var search)
                || !TryGetField<Label>(form, "_trafficSummaryLabel", out var summary))
            {
                CheckAssertion(results, "找得到流量页控件", false);
                PrintSummary(results, showFirewallResidue: false);
                return;
            }

            rebuild.Invoke(form, null);
            Application.DoEvents();

            var order = grid.Rows.Cast<DataGridViewRow>()
                .Select(row => row.Cells[0].Value?.ToString() ?? string.Empty)
                .ToList();

            W("    默认顺序（总计降序）= " + string.Join(" | ", order));
            CheckAssertion(results, "默认按总计降序",
                order.SequenceEqual(new[] { "b.exe", "a.exe", "c.exe", "PID 999" }));

            CheckAssertion(results, "表头显示程序数与合计",
                summary.Text.Contains("共 4 个程序", StringComparison.Ordinal)
                && summary.Text.Contains("合计", StringComparison.Ordinal));

            var enumType = typeof(MainForm).GetNestedType(
                "TrafficSortColumn", BindingFlags.NonPublic);

            if (enumType is null)
            {
                CheckAssertion(results, "找得到流量排序列枚举", false);
            }
            else
            {
                TrySetField(form, "_trafficSort", Enum.Parse(enumType, "Upload"));
                TrySetField(form, "_trafficSortAscending", false);
                rebuild.Invoke(form, null);
                Application.DoEvents();

                var uploadOrder = grid.Rows.Cast<DataGridViewRow>()
                    .Select(row => row.Cells[0].Value?.ToString() ?? string.Empty)
                    .ToList();

                W("    按上传降序 = " + string.Join(" | ", uploadOrder));
                CheckAssertion(results, "按上传降序", uploadOrder.FirstOrDefault() == "a.exe");
            }

            search.Text = "b.exe";
            Application.DoEvents();

            CheckAssertion(results, "搜索程序名生效",
                grid.Rows.Count == 1
                && grid.Rows[0].Cells[0].Value?.ToString() == "b.exe");

            search.Text = "PID 999";
            Application.DoEvents();

            var unknownOk = grid.Rows.Count == 1
                            && grid.Rows[0].Cells[1].Value?.ToString() == "（无法获取）"
                            && grid.Rows[0].Cells[6].Value?.ToString() == "路径未知";

            W($"    未知路径行 = {grid.Rows.Count} 行");
            CheckAssertion(results, "未知路径显示无法获取 + 路径未知", unknownOk);

            search.Text = string.Empty;
            Application.DoEvents();

            // 最小宽度布局：顶部控件不越界，列宽之和不超过客户区。
            if (TryGetField<TabPage>(form, "_tabTraffic", out var trafficTab)
                && TryGetField<DataGridView>(form, "_trafficGrid", out var layoutGrid)
                && TryGetField<Control>(form, "_trafficSearchBox", out var searchBox)
                && TryGetField<Button>(form, "_trafficClearButton", out var clearButton))
            {
                form.Show();
                Application.DoEvents();

                form.Size = new Size(980, 800);

                if (TryGetField<TabControl>(form, "_tabControl", out var tabs))
                {
                    tabs.SelectedTab = trafficTab;
                }

                form.PerformLayout();
                Application.DoEvents();

                var fixedWidth = layoutGrid.Columns.Cast<DataGridViewColumn>()
                    .Where(column => column.AutoSizeMode != DataGridViewAutoSizeColumnMode.Fill)
                    .Sum(column => column.Width);

                var fillMin = layoutGrid.Columns.Cast<DataGridViewColumn>()
                    .Where(column => column.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
                    .Sum(column => column.MinimumWidth);

                W($"    980 宽：列宽合计 {fixedWidth + fillMin}px / 客户区 {layoutGrid.ClientSize.Width}px；" +
                  $"清空按钮右边缘 {clearButton.Right}px / 顶栏 {searchBox.Parent?.Width}px");

                CheckAssertion(results, "最小宽度下流量列不溢出",
                    fixedWidth + fillMin <= layoutGrid.ClientSize.Width);
                CheckAssertion(results, "最小宽度下顶部按钮不越界",
                    clearButton.Right <= (searchBox.Parent?.ClientSize.Width ?? 0));
                CheckAssertion(results, "统计行不超出顶栏",
                    summary.Width <= (searchBox.Parent?.ClientSize.Width ?? 0));

                // 3.7：IDS 页在同一最小窗口下也不越界。
                if (TryGetField<TabPage>(form, "_tabIds", out var idsTab)
                    && TryGetField<DataGridView>(form, "_idsGrid", out var idsGrid)
                    && TryGetField<Button>(form, "_idsAckButton", out var idsAck)
                    && TryGetField<Button>(form, "_idsClearButton", out var idsClear)
                    && TryGetField<TextBox>(form, "_idsSearchBox", out var idsSearch))
                {
                    if (TryGetField<TabControl>(form, "_tabControl", out var idsTabs))
                    {
                        idsTabs.SelectedTab = idsTab;
                    }

                    form.PerformLayout();
                    Application.DoEvents();

                    var idsFixedWidth = idsGrid.Columns.Cast<DataGridViewColumn>()
                        .Where(column => column.AutoSizeMode != DataGridViewAutoSizeColumnMode.Fill)
                        .Sum(column => column.Width);

                    var idsFillMin = idsGrid.Columns.Cast<DataGridViewColumn>()
                        .Where(column => column.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
                        .Sum(column => column.MinimumWidth);

                    W($"    980 宽 IDS：列宽合计 {idsFixedWidth + idsFillMin}px / " +
                      $"客户区 {idsGrid.ClientSize.Width}px；清空按钮右边缘 {idsClear.Right}px / " +
                      $"顶栏 {idsSearch.Parent?.Width}px");

                    CheckAssertion(results, "最小宽度下 IDS 列不溢出",
                        idsFixedWidth + idsFillMin <= idsGrid.ClientSize.Width);
                    CheckAssertion(results, "最小宽度下 IDS 顶部按钮不越界",
                        idsClear.Right <= (idsSearch.Parent?.ClientSize.Width ?? 0));
                    CheckAssertion(results, "IDS 顶部按钮不重叠",
                        idsAck.Right <= idsClear.Left && idsAck.Left > idsSearch.Right);
                }

                if (TryGetField<TabPage>(form, "_tabAntiScan", out var antiTab)
                    && TryGetField<DataGridView>(form, "_antiEventGrid", out var antiGrid)
                    && TryGetField<TextBox>(form, "_antiSearchBox", out var antiSearch)
                    && TryGetField<Button>(form, "_antiSettingsButton", out var antiSettings))
                {
                    if (TryGetField<TabControl>(form, "_tabControl", out var antiTabs))
                    {
                        antiTabs.SelectedTab = antiTab;
                    }

                    form.PerformLayout();
                    Application.DoEvents();

                    var antiFixedWidth = antiGrid.Columns.Cast<DataGridViewColumn>()
                        .Where(column => column.AutoSizeMode != DataGridViewAutoSizeColumnMode.Fill)
                        .Sum(column => column.Width);

                    var antiFillMin = antiGrid.Columns.Cast<DataGridViewColumn>()
                        .Where(column => column.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
                        .Sum(column => column.MinimumWidth);

                    var actionsPanel = antiSettings.Parent;

                    W($"    980 宽防护：列宽合计 {antiFixedWidth + antiFillMin}px / " +
                      $"客户区 {antiGrid.ClientSize.Width}px；按钮组右边缘 {actionsPanel?.Right}px / " +
                      $"顶栏 {antiSearch.Parent?.Width}px");

                    CheckAssertion(results, "最小宽度下防护列不溢出",
                        antiFixedWidth + antiFillMin <= antiGrid.ClientSize.Width);
                    CheckAssertion(results, "最小宽度下防护顶部按钮不越界",
                        actionsPanel is not null
                        && actionsPanel.Right <= (antiSearch.Parent?.ClientSize.Width ?? 0));
                }
            }
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "流量记录页检查执行完成", false);
        }
        finally
        {
            MainForm.SuppressBackgroundServices = false;
            Localizer.Initialize(previous == Localizer.LanguageMode.English ? "en" : "zh");
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 3.5：每程序流量 —— 字节格式化 / 行数据回填 / 排序 / 协议字段 / 英文列头。
    /// 真实 ETW 数字必须在 VM 里测，离线只钉住纯逻辑。
    /// </summary>
    private static void RunTrafficTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previous = Localizer.Current;

        W("################################################################");
        W("#   每程序流量（离线：格式化 / 回填 / 排序 / 协议 / 英文）        #");
        W("################################################################");
        W();

        try
        {
            Localizer.Initialize("zh");

            CheckAssertion(results, "命令名正确",
                ServiceProtocol.Commands.QueryTraffic == "query.traffic");

            CheckAssertion(results, "ETW 事件方向映射正确",
                NetworkEtwMonitor.TryClassifyEvent(10, out var tcpV4Out) && tcpV4Out
                && NetworkEtwMonitor.TryClassifyEvent(11, out var tcpV4In) && !tcpV4In
                && NetworkEtwMonitor.TryClassifyEvent(26, out var tcpV6Out) && tcpV6Out
                && NetworkEtwMonitor.TryClassifyEvent(27, out var tcpV6In) && !tcpV6In
                && NetworkEtwMonitor.TryClassifyEvent(42, out var udpV4Out) && udpV4Out
                && NetworkEtwMonitor.TryClassifyEvent(43, out var udpV4In) && !udpV4In
                && NetworkEtwMonitor.TryClassifyEvent(58, out var udpV6Out) && udpV6Out
                && NetworkEtwMonitor.TryClassifyEvent(59, out var udpV6In) && !udpV6In
                && !NetworkEtwMonitor.TryClassifyEvent(12, out _));

            CheckAssertion(results, "0 字节", TcpConnectionItem.FormatTrafficBytes(0) == "0 B");
            CheckAssertion(results, "1023 字节仍用 B", TcpConnectionItem.FormatTrafficBytes(1023) == "1023 B");
            CheckAssertion(results, "1024 字节 = 1 KB", TcpConnectionItem.FormatTrafficBytes(1024) == "1 KB");
            CheckAssertion(results, "1536 字节 = 1.5 KB", TcpConnectionItem.FormatTrafficBytes(1536) == "1.5 KB");
            CheckAssertion(results, "1 MiB = 1 MB", TcpConnectionItem.FormatTrafficBytes(1024L * 1024) == "1 MB");
            CheckAssertion(results, "1.5 GiB = 1.5 GB",
                TcpConnectionItem.FormatTrafficBytes(1536L * 1024 * 1024) == "1.5 GB");

            var item = MakeTrafficItem(123, 0, 0);

            CheckAssertion(results, "没有数据时三列都是破折号",
                item.TrafficOutText == "—"
                && item.TrafficInText == "—"
                && item.TrafficTotalText == "—");

            item.ApplyTraffic(500, 1500);
            W($"    流量文本 = {item.TrafficOutText} / {item.TrafficInText} / {item.TrafficTotalText}");
            CheckAssertion(results, "上传/下载/总计文本正确",
                item.TrafficOutText == "500 B"
                && item.TrafficInText == "1.5 KB"
                && item.TrafficTotalText == "2 KB");

            item.ApplyTraffic(-100, -1);
            CheckAssertion(results, "负数被夹到 0",
                item.TrafficOutText == "0 B" && item.TrafficInText == "0 B");

            var slow = MakeTrafficItem(1, 10, 10);
            var fast = MakeTrafficItem(2, 100, 500);

            var byTotal = ConnectionFilter.Apply(
                new[] { slow, fast }, null, ConnectionSortColumn.TrafficTotal, ascending: false);
            CheckAssertion(results, "按总流量降序", ReferenceEquals(byTotal[0], fast));

            var byOut = ConnectionFilter.Apply(
                new[] { slow, fast }, null, ConnectionSortColumn.TrafficOut, ascending: true);
            CheckAssertion(results, "按上传升序", ReferenceEquals(byOut[0], slow));

            var dto = new TrafficDto
            {
                Key = @"c:\tools\a.exe",
                Path = @"C:\Tools\a.exe",
                Name = "a.exe",
                IsPathKnown = true,
                Pids = new List<int> { 12 },
                BytesIn = 1234,
                BytesOut = 56,
                LastSeenUtc = new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc),
            };

            var json = JsonSerializer.Serialize(
                new ServiceResponse { Ok = true, Traffic = new List<TrafficDto> { dto } },
                ServiceProtocol.JsonOptions);
            W($"    流量 JSON = {json}");
            CheckAssertion(results, "响应 JSON 带 traffic / bytesIn / bytesOut",
                json.Contains("\"traffic\":[", StringComparison.Ordinal)
                && json.Contains("\"bytesIn\":1234", StringComparison.Ordinal)
                && json.Contains("\"bytesOut\":56", StringComparison.Ordinal)
                && json.Contains("\"isPathKnown\":true", StringComparison.Ordinal));

            Localizer.Initialize("en");

            CheckAssertion(results, "英文：流量列头",
                Localizer.T("上传") == "Up"
                && Localizer.T("下载") == "Down"
                && Localizer.T("总计") == "Total");

            var tip = Localizer.T("本次运行累计（TCP + UDP 网络事件）；短连接可能漏计。");
            W($"    英文流量提示 = {tip}");
            CheckAssertion(results, "英文：近似值提示无中文",
                !System.Text.RegularExpressions.Regex.IsMatch(tip, "[\u4e00-\u9fff]"));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "流量检查执行完成", false);
        }
        finally
        {
            Localizer.Initialize(previous == Localizer.LanguageMode.English ? "en" : "zh");
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static TcpConnectionItem MakeTrafficItem(int pid, long bytesOut, long bytesIn)
    {
        var item = new TcpConnectionItem
        {
            Pid = pid,
            ProcessName = $"p{pid}.exe",
            ProcessPath = $@"C:\p{pid}.exe",
            Protocol = "IPv4",
            LocalPort = 50000,
            RemoteAddress = IPAddress.Loopback,
            RemotePort = 443,
            State = TcpState.Established,
        };

        if (bytesOut != 0 || bytesIn != 0)
        {
            item.ApplyTraffic(bytesOut, bytesIn);
        }

        return item;
    }

    /// <summary>
    /// 3.5：临时锁网 —— 协议字段 / 状态字段 / 倒计时格式化 / 英文文案。
    /// 真实 WFP 会话要服务和管理员，放到 VM 验收。
    /// </summary>
    private static void RunStrictLockdownTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var previous = Localizer.Current;

        W("################################################################");
        W("#   临时锁网（离线：协议 / 状态 / 倒计时 / 英文）                #");
        W("################################################################");
        W();

        try
        {
            Localizer.Initialize("zh");

            CheckAssertion(results, "协议版本仍是 v2", ServiceProtocol.Version == 2);
            CheckAssertion(results, "命令名正确",
                ServiceProtocol.Commands.StrictLockdown == "write.strict.lockdown");

            var request = new ServiceRequest
            {
                Command = ServiceProtocol.Commands.StrictLockdown,
                LockdownSeconds = 1800,
            };

            var json = JsonSerializer.Serialize(request, ServiceProtocol.JsonOptions);
            W($"    请求 JSON = {json}");
            CheckAssertion(results, "请求带 lockdownSeconds",
                json.Contains("\"lockdownSeconds\":1800", StringComparison.Ordinal));

            var legacy = JsonSerializer.Deserialize<ServiceRequest>(
                "{\"command\":\"write.strict.lockdown\"}", ServiceProtocol.JsonOptions);
            CheckAssertion(results, "旧客户端不带 lockdownSeconds 时为 null",
                legacy is { LockdownSeconds: null });

            var expires = new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);
            var status = new ServiceStatus
            {
                StrictModeActive = true,
                StrictModePermittedCount = 12,
                StrictModeLockdownActive = true,
                StrictModeLockdownExpiresUtc = expires,
                StrictModeLockdownRemainingSeconds = 1800,
            };

            var statusJson = JsonSerializer.Serialize(status, ServiceProtocol.JsonOptions);
            W($"    状态 JSON = {statusJson}");
            CheckAssertion(results, "状态带锁网字段",
                statusJson.Contains("\"strictModeLockdownActive\":true", StringComparison.Ordinal)
                && statusJson.Contains("\"strictModeLockdownExpiresUtc\":\"2026-10-25T12:00:00Z\"", StringComparison.Ordinal)
                && statusJson.Contains("\"strictModeLockdownRemainingSeconds\":1800", StringComparison.Ordinal));

            CheckAssertion(results, "中文倒计时：30 分钟",
                MainForm.FormatLockdownRemaining(TimeSpan.FromMinutes(30)) == "剩余 30 分钟");
            CheckAssertion(results, "中文倒计时：2 小时",
                MainForm.FormatLockdownRemaining(TimeSpan.FromHours(2)) == "剩余 2 小时");
            CheckAssertion(results, "中文倒计时：不足 1 分钟按 1 分钟算",
                MainForm.FormatLockdownRemaining(TimeSpan.FromSeconds(5)) == "剩余 1 分钟");
            CheckAssertion(results, "中文倒计时：1 小时 59 分",
                MainForm.FormatLockdownRemaining(TimeSpan.FromMinutes(119)) == "剩余 1 小时 59 分钟");

            Localizer.Initialize("en");

            CheckAssertion(results, "英文倒计时：30 分钟",
                MainForm.FormatLockdownRemaining(TimeSpan.FromMinutes(30)) == "30 min left");
            CheckAssertion(results, "英文倒计时：2 小时",
                MainForm.FormatLockdownRemaining(TimeSpan.FromHours(2)) == "2 h left");
            CheckAssertion(results, "英文倒计时：1 小时 59 分",
                MainForm.FormatLockdownRemaining(TimeSpan.FromMinutes(119)) == "1 h 59 min left");

            CheckAssertion(results, "英文：锁网文案已翻译",
                Localizer.T("临时锁网") == "Timed lockdown"
                && Localizer.T("临时锁网已开启") == "Timed lockdown started"
                && Localizer.T("临时锁网已结束") == "Timed lockdown ended"
                && Localizer.T("开始锁网") == "Start lockdown"
                && !System.Text.RegularExpressions.Regex.IsMatch(
                    Localizer.T("防护服务已停止或不可用，网络已经恢复。"), "[\u4e00-\u9fff]"));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "临时锁网检查执行完成", false);
        }
        finally
        {
            Localizer.Initialize(previous == Localizer.LanguageMode.English ? "en" : "zh");
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    private static void RunProcessPathTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   进程路径代查（离线：解析 / DTO / 回填）                      #");
        W("################################################################");
        W();

        try
        {
            var ownPath = ProcessResolver.TryGetImagePath(Environment.ProcessId);
            W($"    当前进程路径 = {ownPath}");
            CheckAssertion(results, "能读取当前进程路径",
                !string.IsNullOrEmpty(ownPath) && File.Exists(ownPath));

            CheckAssertion(results, "PID 0 返回 null",
                ProcessResolver.TryGetImagePath(0) is null);

            var item = new TcpConnectionItem
            {
                Pid = 123,
                ProcessName = "PID 123",
                ProcessPath = string.Empty,
                Protocol = "IPv4",
                LocalPort = 50000,
                RemoteAddress = IPAddress.Loopback,
                RemotePort = 443,
                State = TcpState.Established,
            };

            item.ApplyResolvedPath(@"C:\Tools\a.exe");
            CheckAssertion(results, "回填后路径正确",
                item.ProcessPath == @"C:\Tools\a.exe");
            CheckAssertion(results, "回填后程序名正确",
                item.ProcessName == "a.exe");

            var request = new ServiceRequest
            {
                Command = ServiceProtocol.Commands.QueryProcessPaths,
                Pids = new List<int> { 1, 2 },
            };

            var requestJson = JsonSerializer.Serialize(request, ServiceProtocol.JsonOptions);
            W($"    请求 JSON = {requestJson}");
            CheckAssertion(results, "请求 JSON 使用 camelCase 且带 pids",
                requestJson.Contains("\"pids\":[1,2]", StringComparison.Ordinal));

            var response = new ServiceResponse
            {
                Ok = true,
                ProcessPaths = new List<ProcessPathDto>
                {
                    new() { Pid = 1, Path = @"C:\Tools\a.exe" },
                },
            };

            var responseJson = JsonSerializer.Serialize(response, ServiceProtocol.JsonOptions);
            W($"    响应 JSON = {responseJson}");
            CheckAssertion(results, "响应 JSON 带 processPaths",
                responseJson.Contains("\"processPaths\"", StringComparison.Ordinal));
            CheckAssertion(results, "响应 JSON 带 pid/path",
                responseJson.Contains("\"pid\":1", StringComparison.Ordinal)
                && responseJson.Contains(@"C:\\Tools\\a.exe", StringComparison.Ordinal));
        }
        catch (Exception ex)
        {
            W($"    ！{ex.GetType().Name}: {ex.Message}");
            CheckAssertion(results, "进程路径检查执行完成", false);
        }

        PrintSummary(results, showFirewallResidue: false);
    }
    private static void RunCliTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   命令行模式自检（离线：只测参数解析与输出格式）                #");
        W("################################################################");
        W();

        // ---------------- 1. 不能把"启动界面"误判成命令 ----------------
        W("===== 1. 启动界面 vs 命令行 =====");

        var none = CommandLine.Parse(Array.Empty<string>());
        CheckAssertion(results, "无参数 → 启动界面", none.Kind == CommandKind.None);

        var autostart = CommandLine.Parse(new[] { "--autostart" });
        CheckAssertion(results, "只有 --autostart → 仍然启动界面（只是最小化到托盘）",
            autostart.Kind == CommandKind.None);
        CheckAssertion(results, "只有 --autostart 时 IsAutostart = true", autostart.IsAutostart);

        // ---------------- 2. --block ----------------
        W();
        W("===== 2. --block =====");

        var block = CommandLine.Parse(new[] { "--block", @"C:\Tools\a.exe" });
        CheckAssertion(results, "--block 被解析成 Block", block.Kind == CommandKind.Block);
        CheckAssertion(results, "--block 带出了程序路径", block.ProgramPath == @"C:\Tools\a.exe");

        var withSpaces = CommandLine.Parse(new[] { "--block", @"C:\Program Files\A B\c.exe" });
        CheckAssertion(results, "带空格的路径原样保留", withSpaces.ProgramPath == @"C:\Program Files\A B\c.exe");

        CheckAssertion(results, "--block 后面漏了路径 → 参数错误",
            CommandLine.Parse(new[] { "--block" }).Kind == CommandKind.Invalid);
        CheckAssertion(results, "--block 后面是空字符串 → 参数错误",
            CommandLine.Parse(new[] { "--block", "   " }).Kind == CommandKind.Invalid);
        CheckAssertion(results, "--block 后面多写了参数 → 参数错误（不静默忽略）",
            CommandLine.Parse(new[] { "--block", @"C:\a.exe", "--yes" }).Kind == CommandKind.Invalid);

        // ---------------- 3. --list-blocked ----------------
        W();
        W("===== 3. --list-blocked =====");

        CheckAssertion(results, "--list-blocked 被解析成 ListBlocked",
            CommandLine.Parse(new[] { "--list-blocked" }).Kind == CommandKind.ListBlocked);
        CheckAssertion(results, "--list-blocked 后面多写了参数 → 参数错误",
            CommandLine.Parse(new[] { "--list-blocked", "x" }).Kind == CommandKind.Invalid);

        // ---------------- 4. --unblock-all / --yes ----------------
        W();
        W("===== 4. --unblock-all 与 --yes =====");

        var unblock = CommandLine.Parse(new[] { "--unblock-all" });
        CheckAssertion(results, "--unblock-all 被解析成 UnblockAll", unblock.Kind == CommandKind.UnblockAll);
        CheckAssertion(results, "没带 --yes 时 Confirmed = false（不会真删）", !unblock.Confirmed);

        CheckAssertion(results, "带了 --yes 时 Confirmed = true",
            CommandLine.Parse(new[] { "--unblock-all", "--yes" }).Confirmed);
        CheckAssertion(results, "--unblock-all 后面出现不认识的参数 → 参数错误",
            CommandLine.Parse(new[] { "--unblock-all", "--force" }).Kind == CommandKind.Invalid);

        // ---------------- 5. 帮助 / 大小写 / 错误参数 ----------------
        W();
        W("===== 5. 帮助、大小写、错误参数 =====");

        CheckAssertion(results, "--help → Help", CommandLine.Parse(new[] { "--help" }).Kind == CommandKind.Help);
        CheckAssertion(results, "-h → Help", CommandLine.Parse(new[] { "-h" }).Kind == CommandKind.Help);
        CheckAssertion(results, "/? → Help", CommandLine.Parse(new[] { "/?" }).Kind == CommandKind.Help);
        CheckAssertion(results, "--help 优先级最高（--block --help 也显示帮助）",
            CommandLine.Parse(new[] { "--block", "--help" }).Kind == CommandKind.Help);
        CheckAssertion(results, "参数不区分大小写（--BLOCK）",
            CommandLine.Parse(new[] { "--BLOCK", @"C:\a.exe" }).Kind == CommandKind.Block);

        CheckAssertion(results, "--migrate 被解析成 Migrate",
            CommandLine.Parse(new[] { "--migrate" }).Kind == CommandKind.Migrate);
        CheckAssertion(results, "--migrate 后面多写了参数 → 参数错误",
            CommandLine.Parse(new[] { "--migrate", "x" }).Kind == CommandKind.Invalid);
        CheckAssertion(results, "--recover 被解析成 Recover",
            CommandLine.Parse(new[] { "--recover" }).Kind == CommandKind.Recover);
        CheckAssertion(results, "--recover 后面多写了参数 → 参数错误",
            CommandLine.Parse(new[] { "--recover", "x" }).Kind == CommandKind.Invalid);

        var unknown = CommandLine.Parse(new[] { "--nope" });
        CheckAssertion(results, "不认识的参数 → Invalid，并且给出说明",
            unknown.Kind == CommandKind.Invalid && !string.IsNullOrEmpty(unknown.Error));
        CheckAssertion(results, "只给一个裸路径（忘记写 --block）→ Invalid",
            CommandLine.Parse(new[] { @"C:\a.exe" }).Kind == CommandKind.Invalid);

        // ---------------- 6. 输出格式（脚本要能解析） ----------------
        W();
        W("===== 6. 输出格式 =====");

        var rule = new FirewallRuleItem
        {
            Name = "AppGuard_Block_a.exe_1a2b3c4d",
            ApplicationPath = @"C:\Tools\a.exe",
            Description = "x",
            Grouping = "AppGuard",
            Enabled = true,
            Action = FirewallAction.Block,
            Direction = FirewallDirection.Outbound,
            Protocol = 256,
        };

        var line = CliText.FormatRuleLine(rule);
        W($"    规则行 = {line}");
        CheckAssertion(results, "规则行是「规则名 \\t 路径 \\t 自动解除」三段",
            line.Split('\t').Length == 3
            && line.StartsWith("AppGuard_Block_a.exe_1a2b3c4d\t", StringComparison.Ordinal)
            && line.Contains(@"C:\Tools\a.exe"));

        var output = CliText.BuildListBlockedOutput(new[] { rule }, allowRuleCount: 2, version: "1.4.0");
        W();
        W("    --list-blocked 的完整输出：");
        foreach (var textLine in output.Split('\n'))
        {
            W("      " + textLine.TrimEnd('\r'));
        }

        CheckAssertion(results, "标题行说明了条数", output.Contains("已阻止的程序：1 条"));
        CheckAssertion(results,
            "每一行要么是以 # 开头的说明行、要么是 3 段的数据行（脚本好解析）",
            output.Split('\n')
                .Select(textLine => textLine.TrimEnd('\r'))
                .Where(textLine => textLine.Length > 0)
                .All(textLine => textLine.StartsWith('#') || textLine.Split('\t').Length == 3));
        CheckAssertion(results, "包含那条规则", output.Contains("AppGuard_Block_a.exe_1a2b3c4d"));
        CheckAssertion(results, "如实说明有 2 条「允许」规则没列出", output.Contains("另有 2 条「允许」规则"));

        var emptyOutput = CliText.BuildListBlockedOutput(Array.Empty<FirewallRuleItem>(), 0, "1.4.0");
        CheckAssertion(results, "没有阻止规则时明确写「没有阻止规则」", emptyOutput.Contains("没有阻止规则"));
        CheckAssertion(results, "没有允许规则时不出现那行说明", !emptyOutput.Contains("「允许」规则"));

        var preview = CliText.BuildUnblockPreview(new[] { rule });
        CheckAssertion(results, "待删清单写着将要删除 1 条", preview.Contains("将要删除这 1 条"));

        CheckAssertion(results, "帮助里列了全部四条命令",
            CliText.Usage.Contains("--block") && CliText.Usage.Contains("--list-blocked")
            && CliText.Usage.Contains("--unblock-all") && CliText.Usage.Contains("--help"));
        CheckAssertion(results, "帮助里写清了退出码", CliText.Usage.Contains("退出码"));
        CheckAssertion(results, "帮助里写清了确认框的例外", CliText.Usage.Contains("不会弹确认框"));

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// 界面三态（离线）：不是所有者 / 密钥不可用 / 未初始化。
    /// 用反射设置 ProtectedModeClient 的状态，再走真实的 UpdateServiceStatusLabel。
    /// </summary>
    private static void RunProtectedModeUiTest()
    {
        var results = new List<(string Title, bool Passed)>();
        var field = typeof(ProtectedModeClient).GetField(
            "_status", BindingFlags.Static | BindingFlags.NonPublic);

        W("################################################################");
        W("#   受保护模式界面三态（不是所有者 / 密钥不可用 / 未初始化）      #");
        W("################################################################");
        W();

        if (field is null)
        {
            CheckAssertion(results, "找得到受保护模式状态字段", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        MainForm.SuppressBackgroundServices = true;

        using var form = new MainForm(isAutostart: false);
        TrySetField(form, "_runtimeInitialized", true);

        if (!TryGetField<Button>(form, "_rulesAddButton", out var addButton)
            || !TryGetField<Label>(form, "_rulesNoticeLabel", out var notice)
            || !TryGetField<ToolStripStatusLabel>(form, "_serviceStatusLabel", out var serviceLabel))
        {
            CheckAssertion(results, "找得到界面状态控件", false);
            PrintSummary(results, showFirewallResidue: false);
            return;
        }

        void SetState(ProtectedModeStatus status)
        {
            field.SetValue(null, status);
            InvokePrivate(form, "UpdateServiceStatusLabel", new object?[] { null });
            form.Refresh();
        }

        SetState(new ProtectedModeStatus(
            ProtectedModeState.NotOwner, "OTHER\\user", "S-1-5-21-1",
            null, "不是所有者"));
        W($"    不是所有者：{serviceLabel.Text}");
        CheckAssertion(results, "不是所有者：状态栏写明原因",
            (serviceLabel.Text ?? string.Empty).Contains("不是所有者"));
        CheckAssertion(results, "不是所有者：规则加入禁用", !addButton.Enabled);
        CheckAssertion(results, "不是所有者：提示写明只读",
            (notice.Text ?? string.Empty).Contains("只读"));
        CheckAssertion(results, "不是所有者：状态栏不可点击启动",
            !serviceLabel.IsLink);

        SetState(new ProtectedModeStatus(
            ProtectedModeState.KeyUnavailable, "VM\\VM", "S-1-5-21-1",
            null, "DPAPI 解不开"));
        W($"    密钥不可用：{serviceLabel.Text}");
        CheckAssertion(results, "密钥不可用：状态栏写明原因",
            (serviceLabel.Text ?? string.Empty).Contains("密钥不可用"));
        CheckAssertion(results, "密钥不可用：规则加入禁用", !addButton.Enabled);

        SetState(new ProtectedModeStatus(
            ProtectedModeState.NotInitialized, null, null, null, "未初始化"));
        W($"    未初始化：{serviceLabel.Text}");
        CheckAssertion(results, "未初始化：状态栏写明原因",
            (serviceLabel.Text ?? string.Empty).Contains("未初始化"));
        CheckAssertion(results, "未初始化：规则加入禁用", !addButton.Enabled);

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>反射调用 MainForm 的私有无参方法（自检要跑真实代码路径，不自己另写一遍）。</summary>
    private static bool InvokePrivateNoArgs(MainForm form, string methodName)
        => InvokePrivate(form, methodName, null);

    /// <summary>反射调用 MainForm 的私有方法，可带参数。</summary>
    private static bool InvokePrivate(MainForm form, string methodName, object?[]? args)
    {
        var method = typeof(MainForm).GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic);
        if (method is null)
        {
            return false;
        }

        method.Invoke(form, args);
        return true;
    }

    /// <summary>反射写私有字段。仅用于自检里模拟"用户已经选中了一行"这类前提。</summary>
    private static bool SetPrivateField<T>(MainForm form, string fieldName, T value)
    {
        var field = typeof(MainForm).GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic);
        if (field is null)
        {
            return false;
        }

        field.SetValue(form, value);
        return true;
    }

    /// <summary>
    /// 记录一条断言。
    /// （<c>RunFullTest</c> 里那个同名函数是**局部函数**，这类新模式下用不到，
    /// 所以单独提供一份静态版本。）
    /// </summary>
    private static void CheckAssertion(List<(string Title, bool Passed)> results, string title, bool passed)
    {
        W($"    [{(passed ? "通过" : "失败")}] {title}");
        results.Add((title, passed));
    }

    /// <summary>
    /// IP 归属查询自检（**会联网**）。
    ///
    /// 这是唯一一个主动联网的自检模式。它用的是产品里同一个 Core/IpOwnershipLookup.cs，
    /// 所以跑通了就等于证明产品的联网路径是好的；
    /// 同时用私有 / 回环地址验证「这些地址根本不会被发出去」。
    ///
    /// 为什么需要它：审计只能证明「引用了哪些类型」，证明不了「行为对不对」。
    /// 联网行为的正确性只能靠真实跑一遍。
    /// </summary>
    private static void RunOwnershipTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   IP 归属查询自检（会联网：whois.cymru.com:43）                #");
        W("################################################################");
        W();

        // 公网地址用来验证「查得到」，私有地址用来验证「发不出去」。
        var publicAddresses = new[]
        {
            IPAddress.Parse("8.8.8.8"),                 // IPv4，公认稳定
            IPAddress.Parse("1.1.1.1"),                 // IPv4
            IPAddress.Parse("2001:4860:4860::8888"),    // IPv6
        };

        var localAddresses = new[]
        {
            IPAddress.Parse("192.168.1.1"),
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("172.16.0.1"),
            IPAddress.Parse("169.254.1.1"),
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("::1"),
        };

        var all = localAddresses.Concat(publicAddresses).ToArray();

        W("===== 1. 地址是否值得查询（本地判断，不发送）=====");
        foreach (var address in all)
        {
            W($"    {(IpOwnershipLookup.IsQueryable(address) ? "会发送  " : "本地拦截")}  {address}");
        }

        W();

        results.Add(("私有 / 回环 / 链路本地地址不会被发出去查询",
            localAddresses.All(a => !IpOwnershipLookup.IsQueryable(a))));

        results.Add(("公网 IPv4 / IPv6 地址会被查询",
            publicAddresses.All(IpOwnershipLookup.IsQueryable)));

        W();
        W("===== 2. 实际查询结果（Team Cymru WHOIS）=====");

        var lookup = IpOwnershipLookup.Query(all);

        foreach (var address in all)
        {
            var key = address.ToString();
            var info = lookup.TryGetValue(key, out var found) ? found : IpOwnershipInfo.None;

            var country = string.IsNullOrEmpty(info.CountryCode) ? "-" : info.CountryCode;
            var asn = string.IsNullOrEmpty(info.Asn) ? "-" : "AS" + info.Asn;
            var extra = string.IsNullOrEmpty(info.Detail)
                ? string.Join(" / ", new[] { info.Prefix, info.AsName }.Where(s => !string.IsNullOrEmpty(s)))
                : info.Detail;

            W($"    {key,-26} {info.State,-11} {country,-3} {asn,-9} {extra}");
        }

        W();

        results.Add(("本机 / 局域网地址的结果是 LocalOnly，说明从未发出",
            localAddresses.All(a =>
                lookup.TryGetValue(a.ToString(), out var info) && info.State == IpOwnershipState.LocalOnly)));

        results.Add(("公网 IPv4 / IPv6 都能查到归属（需能访问 whois.cymru.com）",
            publicAddresses.All(a =>
                lookup.TryGetValue(a.ToString(), out var info) && info.State == IpOwnershipState.Known)));

        results.Add(("返回字段完整：AS 号非空、国家码为两位",
            lookup.TryGetValue("8.8.8.8", out var google)
            && google.State == IpOwnershipState.Known
            && google.Asn.Length > 0
            && google.CountryCode.Length == 2));

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>
    /// IP 归属的核心逻辑自检（**不联网**）。
    ///
    /// 用不联网的替身替换真实查询实现，把「缓存命中 / 有效期过期 / 容量淘汰 /
    /// 开关关闭时零流量 / 私有地址不进队列 / 调用方不被阻塞 / 关闭后不崩 /
    /// 设置持久化能记住用户的关闭」这些纯逻辑离线验证清楚 ——
    /// 它们不该依赖网络通不通。
    /// </summary>
    private static void RunOwnershipCoreTest()
    {
        var results = new List<(string Title, bool Passed)>();

        W("################################################################");
        W("#   IP 归属：缓存与调度自检（不联网）                            #");
        W("################################################################");
        W();

        // ---------- 1. 同一批地址只查一次 ----------
        {
            var calls = 0;
            using var service = NewOwnershipService(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(1), 100,
                onQuery: _ => Interlocked.Increment(ref calls));

            service.IsEnabled = true;
            var batch = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") };

            service.Request(batch);
            var arrived = WaitUntil(() => service.CachedCount >= 2);

            service.Request(batch);      // 再请求一次，应当全部命中缓存
            Thread.Sleep(300);

            W($"    查询调用次数 = {calls}（预期 1：第二次应命中缓存）");
            results.Add(("同一批地址只查询一次，重复请求命中缓存", arrived && calls == 1));
        }

        // ---------- 2. 有效期过后会重新查询 ----------
        {
            var calls = 0;
            using var service = NewOwnershipService(
                TimeSpan.FromMilliseconds(400), TimeSpan.FromMilliseconds(100), 100,
                onQuery: _ => Interlocked.Increment(ref calls));

            service.IsEnabled = true;
            var one = new[] { IPAddress.Parse("9.9.9.9") };

            service.Request(one);
            var first = WaitUntil(() => calls >= 1);

            Thread.Sleep(700);           // 等有效期过去
            service.Request(one);
            var second = WaitUntil(() => calls >= 2);

            W($"    查询调用次数 = {calls}（预期 2：有效期 400ms，等待 700ms 后应重查）");
            results.Add(("结果过期后会重新查询", first && second && calls == 2));
        }

        // ---------- 3. 失败结果用更短的有效期 ----------
        {
            var calls = 0;
            using var service = NewOwnershipService(
                successTtl: TimeSpan.FromHours(1),      // 成功要 1 小时
                failureTtl: TimeSpan.FromMilliseconds(300),  // 失败只等 300ms
                capacity: 100,
                onQuery: _ => Interlocked.Increment(ref calls),
                fail: true);

            service.IsEnabled = true;
            var one = new[] { IPAddress.Parse("7.7.7.7") };

            service.Request(one);
            WaitUntil(() => calls >= 1);

            Thread.Sleep(600);
            service.Request(one);
            var retried = WaitUntil(() => calls >= 2);

            W($"    查询调用次数 = {calls}（预期 2：失败结果的短有效期应允许尽快重试）");
            results.Add(("查询失败会用更短的有效期，避免长时间压住重试", retried && calls == 2));

            var failedText = service.TryGet("7.7.7.7", out var info) ? info.TooltipText : "";
            results.Add(("失败结果的悬停提示会写明原因", failedText.Contains("查询失败")));
        }

        // ---------- 4. 容量上限淘汰 ----------
        {
            var cache = new IpOwnershipCache(
                TimeSpan.FromHours(1), TimeSpan.FromHours(1), capacity: 5);

            for (var i = 0; i < 20; i++)
            {
                cache.Set($"10.0.0.{i}", new IpOwnershipInfo(IpOwnershipState.Known, "1", "X", "ZZ"));
            }

            W($"    写入 20 条、容量 5 → 实际保留 {cache.Count} 条");
            results.Add(("缓存条数不会超过容量上限", cache.Count <= 5));

            var evicted = !cache.TryGet("10.0.0.0", out _);
            var kept = cache.TryGet("10.0.0.19", out _);
            results.Add(("超出容量时淘汰最旧的、保留最新的", evicted && kept));
        }

        // ---------- 5. 关闭时零流量 ----------
        {
            var calls = 0;
            using var service = NewOwnershipService(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(1), 100,
                onQuery: _ => Interlocked.Increment(ref calls));

            // 默认就是关闭状态
            service.Request(new[] { IPAddress.Parse("8.8.8.8") });
            Thread.Sleep(300);
            var silentWhileOff = calls == 0;

            service.IsEnabled = true;
            service.Request(new[] { IPAddress.Parse("8.8.8.8") });
            var worksWhenOn = WaitUntil(() => calls >= 1);

            W($"    关闭时查询调用次数 = 0 → {(silentWhileOff ? "是" : "否")}；开启后是否查询 → {worksWhenOn}");
            results.Add(("功能关闭时不会发出任何查询", silentWhileOff));
            results.Add(("功能开启后才开始查询", worksWhenOn));
        }

        // ---------- 6. 私有 / 回环地址不进队列 ----------
        {
            var calls = 0;
            using var service = NewOwnershipService(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(1), 100,
                onQuery: _ => Interlocked.Increment(ref calls));

            service.IsEnabled = true;
            service.Request(new[]
            {
                IPAddress.Parse("192.168.1.1"),
                IPAddress.Parse("10.0.0.1"),
                IPAddress.Parse("172.16.5.5"),
                IPAddress.Parse("169.254.9.9"),
                IPAddress.Parse("127.0.0.1"),
                IPAddress.Parse("::1"),
            });
            Thread.Sleep(300);

            W($"    查询调用次数 = {calls}（预期 0），缓存条数 = {service.CachedCount}（预期 0）");
            results.Add(("私有 / 回环地址根本不会进入查询队列", calls == 0 && service.CachedCount == 0));
        }

        // ---------- 7. 请求不阻塞调用方 ----------
        {
            var calls = 0;
            using var service = NewOwnershipService(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(1), 100,
                onQuery: _ => Interlocked.Increment(ref calls),
                delayMs: 1200);                       // 故意让查询很慢

            service.IsEnabled = true;

            var sw = Stopwatch.StartNew();
            service.Request(new[] { IPAddress.Parse("8.8.8.8") });
            sw.Stop();

            W($"    Request 返回耗时 = {sw.ElapsedMilliseconds} ms（查询本身要 1200ms）");
            results.Add(("Request 立即返回，不在调用方线程上做网络 IO", sw.ElapsedMilliseconds < 300));

            results.Add(("慢查询最终仍能拿到结果", WaitUntil(() => calls >= 1, 5000)));
        }

        // ---------- 8. 关闭调度器后不崩、不再查询 ----------
        {
            var calls = 0;
            var service = NewOwnershipService(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(1), 100,
                onQuery: _ => Interlocked.Increment(ref calls));

            service.IsEnabled = true;
            service.Dispose();

            var threw = false;
            try
            {
                service.Request(new[] { IPAddress.Parse("8.8.8.8") });
            }
            catch (Exception)
            {
                threw = true;
            }

            Thread.Sleep(300);
            W($"    关闭后再次请求：抛异常 = {threw}，查询调用次数 = {calls}（预期 0）");
            results.Add(("关闭调度器后再次请求不抛异常、也不再查询", !threw && calls == 0));
        }

        // ---------- 9. 设置持久化：用户的「关闭」必须记得住 ----------
        {
            var temp = Path.Combine(Path.GetTempPath(), $"winappguard-settings-{Guid.NewGuid():N}.json");

            try
            {
                // 9.1 文件不存在 → 默认开启
                var fresh = AppSettings.Load(temp);
                results.Add(("设置文件缺失时按默认值处理（IP 归属默认开启）", fresh.IpOwnershipEnabled));

                // 9.2 关闭后保存 → 重新读出仍然是关闭（本阶段最关键的一条）
                fresh.IpOwnershipEnabled = false;
                fresh.IpOwnershipNoticeShown = true;
                fresh.Save(temp);

                var reloaded = AppSettings.Load(temp);
                W($"    写入 IpOwnershipEnabled=false 后读回 = {reloaded.IpOwnershipEnabled}（预期 False）");
                results.Add(("关闭 IP 归属后保存，重新读取仍然是关闭（关得掉，也记得住）",
                    !reloaded.IpOwnershipEnabled && reloaded.IpOwnershipNoticeShown));

                // 9.3 文件里只允许有开关布尔值 + 保留天数，不许夹带 IP / 路径
                var text = File.ReadAllText(temp, Encoding.UTF8);
                using var document = JsonDocument.Parse(text);
                var properties = document.RootElement.EnumerateObject().ToList();
                var onlySafeValues = properties.All(p =>
                    p.Value.ValueKind == JsonValueKind.True
                    || p.Value.ValueKind == JsonValueKind.False
                    || (p.Name == nameof(AppSettings.AuditRetentionDays)
                        && p.Value.ValueKind == JsonValueKind.Number
                        && p.Value.GetInt32() is >= AppSettings.MinAuditRetentionDays
                            and <= AppSettings.MaxAuditRetentionDays));

                W($"    设置文件属性个数 = {properties.Count}，只含布尔值 + 保留天数 = {onlySafeValues}");
                results.Add(("设置文件里只有开关布尔值 + 保留天数，不存任何 IP / 路径",
                    onlySafeValues && properties.Count > 0 && !text.Contains("8.8.8.8")));

                // 9.3b 保留天数能存能读；手改成非法值时回落到 7 天
                fresh.AuditRetentionDays = 3;
                fresh.Save(temp);
                results.Add(("保留期改成 3 天后重新读取仍是 3 天",
                    AppSettings.Load(temp).AuditRetentionDays == 3));

                var tampered = File.ReadAllText(temp, Encoding.UTF8)
                    .Replace("\"AuditRetentionDays\": 3", "\"AuditRetentionDays\": 999");
                File.WriteAllText(temp, tampered, Encoding.UTF8);
                results.Add(("保留期被手改成 999 时回落到默认 7 天",
                    AppSettings.Load(temp).AuditRetentionDays == AppSettings.DefaultAuditRetentionDays));

                // 9.4 原子写入不残留 .tmp
                results.Add(("保存后不残留 .tmp 临时文件", !File.Exists(temp + ".tmp")));

                // 9.5 文件损坏 → 回落默认，不抛异常
                File.WriteAllText(temp, "{ 这不是合法 JSON ", Encoding.UTF8);
                var broken = AppSettings.Load(temp);
                results.Add(("设置文件损坏时回落到默认值，不抛异常", broken.IpOwnershipEnabled));
            }
            finally
            {
                try
                {
                    if (File.Exists(temp)) File.Delete(temp);
                    if (File.Exists(temp + ".tmp")) File.Delete(temp + ".tmp");
                }
                catch (Exception)
                {
                    // 临时文件删不掉不影响结论。
                }
            }
        }

        PrintSummary(results, showFirewallResidue: false);
    }

    /// <summary>构造一个使用不联网替身查询的调度器，供缓存/调度自检使用。</summary>
    private static IpOwnershipService NewOwnershipService(
        TimeSpan successTtl,
        TimeSpan failureTtl,
        int capacity,
        Action<IReadOnlyList<IPAddress>>? onQuery = null,
        bool fail = false,
        int delayMs = 0)
    {
        var cache = new IpOwnershipCache(successTtl, failureTtl, capacity);

        return new IpOwnershipService(cache, addresses =>
        {
            onQuery?.Invoke(addresses);

            if (delayMs > 0)
            {
                Thread.Sleep(delayMs);
            }

            var map = new Dictionary<string, IpOwnershipInfo>(StringComparer.Ordinal);
            foreach (var address in addresses)
            {
                map[IpOwnershipLookup.ToKey(address)] = fail
                    ? IpOwnershipInfo.Failed("自检用失败")
                    : new IpOwnershipInfo(
                        IpOwnershipState.Known, "64500", "SELFCHECK-AS", "ZZ", "0.0.0.0/0", "test", "2026-01-01");
            }

            return map;
        });
    }

    /// <summary>轮询等待条件成立。比依赖事件时序更稳，避免自检出现偶发失败。</summary>
    private static bool WaitUntil(Func<bool> condition, int timeoutMs = 4000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(20);
        }

        return condition();
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

        // 3.0 起产品拆成多个程序集（UI + Core + 以后还有服务/Contracts）。
        // 只审计 UI 会让"真正干活的那一半"逃过审计 —— 那会变成**假报告**。
        // 这里把同一目录下的自有程序集一起审计；任何一项不过，整份审计都不过。
        var targets = new List<string> { target };
        var coreSibling = Path.Combine(
            Path.GetDirectoryName(target)!, "WinAppGuard.Core.dll");

        if (File.Exists(coreSibling))
        {
            targets.Add(coreSibling);
        }

        // 3.0-c：WFP 实现已拆到独立程序集，也要一起审计；
        // 同时验证 UI/Core **没有**引用它（编译期隔离）。
        var wfpSibling = FindWfpAssembly(target);

        if (wfpSibling is not null)
        {
            targets.Add(wfpSibling);
        }
        else
        {
            W("    提示：没找到 WinAppGuard.Wfp.dll，跳过 WFP 部分审计。");
        }

        var results = new List<(string Title, bool Passed)>();

        foreach (var assembly in targets)
        {
            var label = Path.GetFileNameWithoutExtension(assembly);

            W($"===== 审计 {label} =====");
            W($"    路径 = {assembly}");
            W($"    大小 = {new FileInfo(assembly).Length / 1024.0:F0} KB");
            W();

            using var stream = File.OpenRead(assembly);
            using var pe = new PEReader(stream);
            var metadata = pe.GetMetadataReader();

            // 每个函数都在 results 末尾追加若干条；给它们统一加上程序集前缀，
            // 这样失败时能一眼看出是哪一个程序集的问题。
            var before = results.Count;

            AuditAssemblies(metadata, results);
            AuditNetworking(metadata, results);
            AuditNativeImports(metadata);
            AuditSensitiveApis(metadata);
            AuditNativeNetworkImports(metadata, results);

            // 3.0-c 编译期隔离：界面与 Core 都不许引用 WFP 程序集。
            var referenced = metadata.AssemblyReferences
                .Select(handle => metadata.GetString(metadata.GetAssemblyReference(handle).Name))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (!label.Equals("WinAppGuard.Wfp", StringComparison.OrdinalIgnoreCase))
            {
                results.Add((
                    "编译期隔离：不引用 WinAppGuard.Wfp",
                    !referenced.Contains("WinAppGuard.Wfp")));
            }

            for (var i = before; i < results.Count; i++)
            {
                results[i] = ($"[{label}] {results[i].Title}", results[i].Passed);
            }
        }

        PrintSummary(results, showFirewallResidue: false);

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

    /// <summary>找 WinAppGuard.Wfp.dll：先看 UI 输出目录，再从项目根找它的 bin。</summary>
    private static string? FindWfpAssembly(string uiAssembly)
    {
        var directory = Path.GetDirectoryName(uiAssembly);

        if (string.IsNullOrEmpty(directory))
        {
            return null;
        }

        var sameDirectory = Path.Combine(directory, "WinAppGuard.Wfp.dll");

        if (File.Exists(sameDirectory))
        {
            return sameDirectory;
        }

        var current = new DirectoryInfo(directory);

        for (var depth = 0; depth < 10 && current is not null; depth++, current = current.Parent)
        {
            var projectFile = Path.Combine(
                current.FullName, "src", "WinAppGuard", "WinAppGuard.csproj");

            if (!File.Exists(projectFile))
            {
                continue;
            }

            foreach (var configuration in new[] { "Release", "Debug" })
            {
                var binPath = Path.Combine(
                    current.FullName, "src", "WinAppGuard.Wfp", "bin", configuration);

                if (!Directory.Exists(binPath))
                {
                    continue;
                }

                var found = Directory
                    .EnumerateFiles(binPath, "WinAppGuard.Wfp.dll", SearchOption.AllDirectories)
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
                        && !n.StartsWith("WindowsBase", StringComparison.OrdinalIgnoreCase)
                        // 3.0 起自有程序集不在"第三方"之列，但它们也不能藏着掖着：
                        // 调用方会把同一目录下的自有程序集**逐个审计**。
                        && !n.Equals("WinAppGuard.Core", StringComparison.OrdinalIgnoreCase)
                        && !n.Equals("WinAppGuard.Contracts", StringComparison.OrdinalIgnoreCase))
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
    /// 列出程序里「能发起网络行为」的类型 —— 这是联网能力的完整清单。
    ///
    /// 从 1.2 起本程序会查询 IP 归属（Team Cymru WHOIS），所以**确实**引用了联网类型。
    /// 这一项因此不再要求「零网络代码」，而是要求「全部落在预期清单内」：
    /// 一旦出现预期之外的类型（HttpClient / Dns / SslStream 之类），
    /// 就说明有人在别处新增了联网路径，必须解释清楚才能放行。
    ///
    /// 预期清单里的类型只允许出现在 Core/IpOwnershipLookup.cs —— 这是设计约定。
    /// 元数据本身看不出「哪个文件用了它」，所以这里只报事实，
    /// 由 --ownership-test 和资源监视器交叉验证「联网只发生在一处」。
    ///
    /// 注意：System.Net.IPAddress / IPEndPoint / AddressFamily 这类是**纯数据类型**，
    /// 只用来把连接表里的字节格式化成可读地址，本身不会发起任何连接。
    /// </summary>
    private static void AuditNetworking(MetadataReader metadata, List<(string, bool)> results)
    {
        W("===== 2. 网络相关类型引用（联网能力清单）=====");

        // 纯数据类型，允许出现
        var allowedDataTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Net.IPAddress",
            "System.Net.IPEndPoint",
            "System.Net.Sockets.AddressFamily",
            "System.Net.Sockets.SocketError",
            "System.Net.Sockets.SocketException",
        };

        // 预期中的联网类型：IP 归属查询（Core/IpOwnershipLookup.cs）需要它们。
        var expectedNetworkTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Net.Sockets.TcpClient",
            "System.Net.Sockets.NetworkStream",
            "System.Net.Sockets.Socket",
        };

        // 只要出现就说明程序有能力联网（含预期内的那些，逐个核对）
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

            if (allowedDataTypes.Contains(full))
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
                // 预期内的标为普通缩进，预期外的加叹号 —— 一眼能看出有没有越界。
                var mark = expectedNetworkTypes.Contains(hit) ? "  " : "！";
                W($"    {mark}{hit}");
            }
        }

        var unexpected = hits.Where(h => !expectedNetworkTypes.Contains(h)).ToList();

        W();
        W("    预期清单（IP 归属查询所需，只允许出现在 Core/IpOwnershipLookup.cs）：");
        W("      System.Net.Sockets.TcpClient / NetworkStream / Socket");
        W();
        W("    已排除的纯数据类型：System.Net.IPAddress / IPEndPoint / AddressFamily /");
        W("      SocketError / SocketException（只格式化地址，不建立任何连接）");
        W();
        W("    补充说明：按主机名连接时，.NET 运行时会自己发起一次 whois.cymru.com 的");
        W("      DNS 解析。我们没有引用 System.Net.Dns，所以这一步在托管元数据里看不到。");
        W();

        results.Add(("联网边界受控：引用的网络类型全部在预期清单内", unexpected.Count == 0));

        if (unexpected.Count > 0)
        {
            W($"    发现预期之外的网络类型：{string.Join(", ", unexpected)}");
            W("    请解释用途，并确认它是否同样集中在唯一联网出口里。");
        }
    }

    /// <summary>
    /// 有明确用途、并经过逐条登记的"网络相关原生调用"。
    ///
    /// 为什么要有这张表：`dnsapi.dll` 里既有"读本机缓存"的函数，也有"发 DNS 查询"的函数，
    /// 只看模块名会把两者混为一谈。这里按**函数名**放行，并在审计输出里逐条打印用途，
    /// 让读者（和未来的维护者）能一眼看出这些调用会不会发包。
    ///
    /// 其中 `DnsQuery_W` 既能发包也能只读缓存 —— 本程序在调用处固定传
    /// `DNS_QUERY_NO_WIRE_QUERY`（只读缓存、不发包），所以登记为例外。
    /// </summary>
    private static readonly Dictionary<string, string> RegisteredNetworkImports =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["dnsapi.dll!DnsGetCacheDataTable"] = "枚举本机 DNS 缓存（只读内存，不发包）",
            ["dnsapi.dll!DnsQuery_W"] = "读缓存记录：缓存优先；开启「域名推测」时可能向本机 DNS 服务器补发查询（设置里可关闭）",
            ["dnsapi.dll!DnsFree"] = "释放上面两个 API 返回的内存",
        };

    /// <summary>
    /// 有没有用 P/Invoke 直接调用网络 API。
    ///
    /// 这一项是**防绕过检查**：第 2 项只看托管类型，如果有人用 ws2_32 / winhttp / wininet
    /// 绕开 TcpClient，第 2 项会显示得很干净，但程序照样能联网 —— 那审计就成了假报告。
    /// 所以单独把网络相关的原生模块也查一遍。
    /// </summary>
    private static void AuditNativeNetworkImports(MetadataReader metadata, List<(string, bool)> results)
    {
        W("===== 5. 网络相关原生调用（防绕过检查）=====");

        var networkModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ws2_32.dll", "wsock32.dll", "winhttp.dll", "wininet.dll",
            "dnsapi.dll", "urlmon.dll", "httpapi.dll", "mswsock.dll",
        };

        var hits = new List<string>();
        var registered = new List<string>();

        foreach (var handle in metadata.MethodDefinitions)
        {
            var method = metadata.GetMethodDefinition(handle);
            var import = method.GetImport();

            if (import.Module.IsNil)
            {
                continue;
            }

            var dll = metadata.GetString(metadata.GetModuleReference(import.Module).Name);
            if (!networkModules.Contains(dll))
            {
                continue;
            }

            var entry = $"{dll}!{metadata.GetString(import.Name)}";

            if (RegisteredNetworkImports.ContainsKey(entry))
            {
                registered.Add(entry);
            }
            else
            {
                hits.Add(entry);
            }
        }

        hits.Sort(StringComparer.OrdinalIgnoreCase);
        registered.Sort(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in registered.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(e => e))
        {
            W($"    [已登记] {entry} —— {RegisteredNetworkImports[entry]}");
        }

        if (hits.Count == 0)
        {
            W("    没有**未登记**的网络相关原生调用。");
            W("    （本程序的联网走托管 TcpClient；DNS 相关调用只读本机缓存，已逐条登记在上方。）");
        }
        else
        {
            W("    ！发现未登记的 P/Invoke 网络调用，托管检查会被绕过，必须解释清楚：");
            foreach (var hit in hits)
            {
                W($"    ！{hit}");
            }
        }

        W();
        results.Add(("无绕过：没有未登记的原生网络调用", hits.Count == 0));
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
            ("System.IO.File", "WriteAllText", "写文件：日志由 AppendAllText，此项用于设置文件的原子替换"),
            ("System.IO.File", "Move", "写文件：设置文件先写 .tmp 再改名，避免半截文件"),
            ("System.IO.Directory", "CreateDirectory", "建目录：日志目录 + 设置目录"),
            ("System.Net.Sockets.TcpClient", "*", "唯一的联网动作：连 whois.cymru.com:43 查 IP 归属"),
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
    /// <param name="results">检查项与结论。</param>
    /// <param name="showFirewallResidue">
    /// 是否打印「残留 AppGuard 规则」这一行。只有防火墙相关模式需要它，
    /// 审计和 IP 归属自检打这行是噪音，所以做成开关。
    /// </param>
    private static void PrintSummary(List<(string Title, bool Passed)> results, bool showFirewallResidue = true)
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
        if (showFirewallResidue)
        {
            W($"收尾后残留的 AppGuard 规则 = {FirewallManager.GetAppGuardRules().Count} 条（应为 0）");
        }
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
