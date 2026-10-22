using WinAppGuard.Interop;

namespace WinAppGuard.Core;

/// <summary>
/// 单实例控制。
///
/// 为什么需要这一层：没有它的话，用户第二次双击 exe 会真的启动第二个进程，
/// 托盘里就出现两个一模一样的图标 —— 看起来像程序坏了。
/// 更麻烦的是**两个实例会同时操作防火墙和计划任务**，操作可能互相打架，
/// 用户也搞不清该关哪一个。
///
/// 做法：
///   1. 用一个命名互斥体判断是否已经有实例在跑；
///   2. 已经有的话，**不启动新窗口**，而是给已有实例广播一条自定义消息，
///      请它把自己的窗口显示出来；
///   3. 然后本次进程安静退出。
///
/// 这样用户点两下的效果就是「窗口回到前台」，符合直觉，也不会多出图标。
/// </summary>
public static class SingleInstance
{
    /// <summary>
    /// 互斥体名字。
    /// 不带 Global\ 前缀，即按登录会话隔离 —— 一个用户一个实例就够了，
    /// 不同用户各自有托盘图标也是合理的。而且 Global\ 需要额外权限，没必要冒这个险。
    /// </summary>
    private const string MutexName = "WinAppGuard.SingleInstance";

    /// <summary>自定义消息的名字。系统保证同一个字符串在所有进程里得到同一个编号。</summary>
    private const string ShowWindowMessageName = "WinAppGuard.ShowMainWindow";

    private static Mutex? _mutex;

    /// <summary>
    /// 自定义窗口消息的编号。0 表示注册失败（极罕见），此时功能降级为「不显示已有窗口」。
    /// </summary>
    public static uint ShowWindowMessage { get; private set; }

    /// <summary>
    /// 尝试成为唯一实例。
    /// </summary>
    /// <returns>本次是第一个实例返回 true；已经有实例在跑返回 false。</returns>
    public static bool TryAcquire()
    {
        // 必须在判断之前先注册消息：发送方和接收方都要注册，才能拿到同一个编号。
        ShowWindowMessage = NativeMethods.RegisterWindowMessageW(ShowWindowMessageName);

        try
        {
            _mutex = new Mutex(initiallyOwned: true, MutexName, out var isFirstInstance);

            if (!isFirstInstance)
            {
                // 没抢到就不持有它，释放掉避免留着没用的句柄。
                _mutex.Dispose();
                _mutex = null;
            }

            return isFirstInstance;
        }
        catch (UnauthorizedAccessException)
        {
            // 已有一个**更高完整性级别**的实例在跑（例如开机自启的 HIGHEST 任务）：
            // 普通权限进程打不开它的互斥体。不要再开第二个 —— 托盘里出现两个图标更糟。
            return false;
        }
        catch (Exception)
        {
            // 互斥体创建失败（权限、名称冲突等）时按「允许启动」处理 ——
            // 宁可多开一个实例，也不要因为单实例检查本身出错而让程序起不来。
            return true;
        }
    }

    /// <summary>
    /// 广播一条消息，请求已有的那个实例把主窗口显示出来。
    /// </summary>
    public static void RequestShowMainWindow()
    {
        if (ShowWindowMessage == 0)
        {
            return;
        }

        NativeMethods.PostMessageW(
            NativeMethods.HWND_BROADCAST, ShowWindowMessage, IntPtr.Zero, IntPtr.Zero);
    }
}
