using System.Security.Principal;
using System.Xml.Linq;

namespace WinAppGuard.Core;

/// <summary>开机自启的配置状态。</summary>
public enum AutoStartState
{
    /// <summary>系统里没有这个计划任务。</summary>
    NotConfigured,

    /// <summary>任务存在，并且配置正确。</summary>
    Enabled,

    /// <summary>任务存在，但内容和本程序期望的不一致（最常见的原因是程序被挪到别的目录了）。</summary>
    Misconfigured,
}

/// <summary>
/// 开机自启的当前状态。
/// </summary>
/// <param name="State">配置状态。</param>
/// <param name="ExecutablePath">任务里配置要启动的程序路径。</param>
/// <param name="Arguments">任务里配置的命令行参数。</param>
/// <param name="RunLevel">运行级别（原始值，HighestAvailable 表示最高权限）。</param>
/// <param name="Trigger">触发器的人话描述。</param>
/// <param name="TaskState">任务计划程序报告的任务状态。</param>
/// <param name="RawXml">任务的原始 XML 定义 —— 直接给用户看，这是最彻底的「透明」。</param>
public sealed record AutoStartStatus(
    AutoStartState State,
    string ExecutablePath,
    string Arguments,
    string RunLevel,
    string Trigger,
    string TaskState,
    string RawXml)
{
    /// <summary>系统里是否存在这个任务。</summary>
    public bool Exists => State != AutoStartState.NotConfigured;
}

/// <summary>
/// 开机自启管理。用 Windows 任务计划程序实现（需求要求，不用注册表 Run 键）。
///
/// 为什么不用 schtasks.exe 命令行：
///   实测发现它的 XML 输出声明写着 encoding="UTF-16"，实际字节却是单字节编码，
///   解析出来的中文路径可能是乱码；而且 /TR 参数的引号转义很脆弱，路径带空格就出事。
///   改用任务计划程序的 COM 接口（Schedule.Service）后，拿到的是真正的 Unicode 字符串，
///   也没有命令行引号问题。
///
/// ============================ 安全约定 ============================
/// 本类是**整个程序唯一一处会往系统里写持久化配置**的地方，因此：
///   1. 任务名固定为 WinAppGuard（见 AppConstants），绝不使用随机名或隐藏名；
///   2. 只创建、只删除这一个固定名字的任务，绝不碰别人的任务；
///   3. 任务内容对用户完全可见（界面直接把原始 XML 显示出来）；
///   4. 用户可以随时在界面上一键删除，也可以在 taskschd.msc 里手动删除。
/// ==================================================================
///
/// 线程要求：COM 对象有线程亲和性，请**只在界面线程（STA）上调用本类**。
/// </summary>
public static class AutoStartManager
{
    private const string ServiceProgId = "Schedule.Service";

    // ---- 以下常量来自 taskschd.h，数值不能改动 ----

    /// <summary>TASK_CREATE_OR_UPDATE：任务已存在时覆盖它。</summary>
    private const int TaskCreateOrUpdate = 6;

    /// <summary>TASK_LOGON_INTERACTIVE_TOKEN：以当前登录用户的交互式令牌运行。</summary>
    private const int TaskLogonInteractiveToken = 3;

    /// <summary>TASK_RUNLEVEL_HIGHEST：以最高权限运行（开机启动时不会弹 UAC）。</summary>
    private const int TaskRunLevelHighest = 1;

    /// <summary>TASK_TRIGGER_LOGON：用户登录时触发。</summary>
    private const int TaskTriggerLogon = 9;

    /// <summary>TASK_ACTION_EXEC：执行一个程序。</summary>
    private const int TaskActionExec = 0;

    /// <summary>TASK_INSTANCES_IGNORE_NEW：已经有实例在跑时不再启动新的。</summary>
    private const int TaskInstancesIgnoreNew = 2;

    /// <summary>任务所在的文件夹。放在根目录，用户在「任务计划程序」里一眼就能看到。</summary>
    private const string TaskFolderPath = "\\";

    /// <summary>任务内容说明，直接写进任务计划程序的「描述」列，用户悬停就能看到。</summary>
    private const string TaskDescription =
        "由 WinAppGuard 创建：登录 Windows 时自动启动本程序，并直接最小化到系统托盘。" +
        "可以在 WinAppGuard 的「设置」页里关闭它，也可以在任务计划程序里直接删除。";

    // ==================================================================
    // 查询
    // ==================================================================

    /// <summary>
    /// 读取开机自启的当前状态。**只读**，不做任何修改。
    /// </summary>
    public static AutoStartStatus GetStatus()
    {
        var service = CreateTaskService();
        var folder = service.GetFolder(TaskFolderPath);
        var expectedPath = Environment.ProcessPath ?? string.Empty;

        object? found = null;
        foreach (var item in folder.GetTasks(0))
        {
            var name = Convert.ToString(item.Name) ?? string.Empty;
            if (string.Equals(name, AppConstants.ScheduledTaskName, StringComparison.OrdinalIgnoreCase))
            {
                found = item;
                break;
            }
        }

        if (found is null)
        {
            return new AutoStartStatus(
                AutoStartState.NotConfigured,
                string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        dynamic task = found;

        // 注意：这里必须显式声明成 string / int，不能写 var。
        // 因为 task.Xml、task.State 是动态类型，用 var 会让整条表达式都变成动态调用，
        // 后面的元组解构和静态方法调用就都推不出类型了。
        string xml = Convert.ToString(task.Xml) ?? string.Empty;
        string taskState = DescribeTaskState(Convert.ToInt32(task.State));

        var (exe, args, runLevel, trigger) = ParseTaskXml(xml);

        // 配置对不对：要启动的程序必须就是当前这个 exe，参数必须就是 --autostart。
        // 最常见的「不对」是用户把 exe 挪到了别的目录，任务还指着旧路径。
        var isCorrect = string.Equals(exe, expectedPath, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(args.Trim(), AppConstants.AutostartArgument, StringComparison.OrdinalIgnoreCase);

        return new AutoStartStatus(
            isCorrect ? AutoStartState.Enabled : AutoStartState.Misconfigured,
            exe, args, runLevel, trigger, taskState, xml);
    }

    // ==================================================================
    // 开启 / 关闭
    // ==================================================================

    /// <summary>
    /// 创建（或更新）开机自启任务。
    /// </summary>
    /// <param name="executablePath">要自启的程序完整路径。</param>
    public static void Enable(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new ArgumentException("程序路径不能为空。", nameof(executablePath));
        }

        var fullPath = Path.GetFullPath(executablePath);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"找不到要自启的程序：{fullPath}", fullPath);
        }

        var currentUser = WindowsIdentity.GetCurrent().Name;

        var service = CreateTaskService();
        var folder = service.GetFolder(TaskFolderPath);
        var task = service.NewTask(0);

        // ---- 任务说明：让用户在任务计划程序里一眼看懂这是什么 ----
        task.RegistrationInfo.Description = TaskDescription;
        task.RegistrationInfo.Author = "WinAppGuard";

        // ---- 运行身份：以当前用户 + 最高权限运行，这样开机启动不会弹 UAC ----
        task.Principal.RunLevel = TaskRunLevelHighest;
        task.Principal.LogonType = TaskLogonInteractiveToken;
        task.Principal.UserId = currentUser;
        task.Principal.DisplayName = "WinAppGuard";

        // ---- 触发器：当前用户登录时 ----
        var trigger = task.Triggers.Create(TaskTriggerLogon);
        trigger.Enabled = true;
        trigger.UserId = currentUser;

        // ---- 动作：启动本程序并带上 --autostart ----
        var action = task.Actions.Create(TaskActionExec);
        action.Path = fullPath;
        action.Arguments = AppConstants.AutostartArgument;
        action.WorkingDirectory = Path.GetDirectoryName(fullPath) ?? string.Empty;

        var settings = task.Settings;
        settings.Enabled = true;

        // ★ 必须设为不限时长。
        //   任务计划程序新建任务的默认执行上限是 72 小时，
        //   而本程序是常驻托盘的，到点会被计划程序直接杀掉。
        settings.ExecutionTimeLimit = "PT0S";

        // 本程序是常驻的，不要因为「空闲」或「切到电池」就被停掉。
        settings.DisallowStartIfOnBatteries = false;
        settings.StopIfGoingOnBatteries = false;
        settings.AllowHardTerminate = false;
        settings.IdleSettings.StopOnIdleEnd = false;
        settings.StartWhenAvailable = true;

        // 已经有一个实例在跑时不要再启动第二个（托盘出现两个图标会很困惑）。
        settings.MultipleInstances = TaskInstancesIgnoreNew;

        folder.RegisterTaskDefinition(
            AppConstants.ScheduledTaskName,
            task,
            TaskCreateOrUpdate,
            null,
            null,
            TaskLogonInteractiveToken,
            null);
    }

    /// <summary>
    /// 删除开机自启任务。任务本来就不存在时安静返回，不报错。
    /// </summary>
    /// <returns>确实删掉了返回 true；本来就不存在返回 false。</returns>
    public static bool Disable()
    {
        var service = CreateTaskService();
        var folder = service.GetFolder(TaskFolderPath);

        if (!TaskExists(folder))
        {
            return false;
        }

        folder.DeleteTask(AppConstants.ScheduledTaskName, 0);
        return true;
    }

    // ==================================================================
    // 内部工具
    // ==================================================================

    /// <summary>
    /// 判断任务是否存在。
    /// 不用 GetTask() 是因为它在任务不存在时会抛 COM 异常，用异常来表达「不存在」不够清楚。
    /// </summary>
    private static bool TaskExists(dynamic folder)
    {
        foreach (var item in folder.GetTasks(0))
        {
            var name = Convert.ToString(item.Name) ?? string.Empty;
            if (string.Equals(name, AppConstants.ScheduledTaskName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>连接本机的任务计划程序服务。</summary>
    private static dynamic CreateTaskService()
    {
        var type = Type.GetTypeFromProgID(ServiceProgId, throwOnError: false);

        if (type is null)
        {
            throw new PlatformNotSupportedException(
                $"当前系统没有注册 COM 组件 {ServiceProgId}，无法操作任务计划程序。");
        }

        dynamic service = Activator.CreateInstance(type)
            ?? throw new PlatformNotSupportedException($"无法创建 COM 组件 {ServiceProgId} 的实例。");

        // 不带参数 = 连接本机、使用当前用户的凭据。
        service.Connect();
        return service;
    }

    /// <summary>从任务 XML 里取出我们关心的几项。</summary>
    private static (string Exe, string Args, string RunLevel, string Trigger) ParseTaskXml(string xml)
    {
        try
        {
            var document = XDocument.Parse(xml);

            // 任务计划程序的 XML 有命名空间，查询时必须带上，否则什么都找不到。
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

            var exec = document.Descendants(ns + "Exec").FirstOrDefault();
            var exe = exec?.Element(ns + "Command")?.Value ?? string.Empty;
            var args = exec?.Element(ns + "Arguments")?.Value ?? string.Empty;
            var runLevel = document.Descendants(ns + "RunLevel").FirstOrDefault()?.Value ?? string.Empty;

            var trigger = document.Descendants(ns + "LogonTrigger").Any()
                ? "用户登录时"
                : "（无法识别）";

            return (exe, args, runLevel, trigger);
        }
        catch (Exception)
        {
            // 解析失败不影响「任务存在」这个事实，界面上会显示「无法解析」。
            return (string.Empty, string.Empty, string.Empty, "（无法解析）");
        }
    }

    /// <summary>把任务状态码翻成人话。数值来自 taskschd.h 的 TASK_STATE。</summary>
    private static string DescribeTaskState(int state) => state switch
    {
        0 => "未知",
        1 => "已禁用",
        2 => "已排队",
        3 => "就绪",
        4 => "正在运行",
        _ => $"未知({state})",
    };
}
