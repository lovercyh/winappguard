using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts;

namespace WinAppGuard;

/// <summary>
/// 以普通权限运行时，把写命令交给**提权助手**执行（3.0-c）。
///
/// 为什么需要它：服务端要求 `write.*` 命令的客户端令牌已提权（M1.5），
/// 而界面已经改成 asInvoker。写操作因此走一次 UAC：
///   - 界面把 ServiceRequest 写进临时 JSON；
///   - 用 runas 启动 `WinAppGuardSvc.exe --elevated-ipc <req> <resp>`；
///   - 助手以提权身份连服务、执行、把 ServiceResponse 写回文件；
///   - 界面读回响应并清理临时文件。
///
/// 只转发 `write.*` 命令；其它命令界面自己就能发，没必要提权。
/// 用户取消 UAC 时返回 <see cref="CancelledMessage"/>，调用方不应再弹错误框。
/// </summary>
internal static class ElevatedClient
{
    internal const string CancelledMessage = "已取消管理员授权";

    private const int UacCancelledError = 1223;

    /// <summary>提权执行一条写命令。失败返回 null，并通过 <paramref name="error"/> 说明原因。</summary>
    internal static ServiceResponse? TryRequest(ServiceRequest request, out string? error)
    {
        error = null;

        if (!request.Command.StartsWith("write.", StringComparison.OrdinalIgnoreCase))
        {
            error = "内部错误：只有写命令才需要提权。";
            return null;
        }

        var helper = Path.Combine(AppContext.BaseDirectory, "WinAppGuardSvc.exe");

        if (!File.Exists(helper))
        {
            error = "找不到 WinAppGuardSvc.exe（提权助手），请重新安装。";
            return null;
        }

        var requestPath = Path.Combine(
            Path.GetTempPath(), $"wag-elevated-req-{Guid.NewGuid():N}.json");
        var responsePath = Path.Combine(
            Path.GetTempPath(), $"wag-elevated-resp-{Guid.NewGuid():N}.json");

        try
        {
            File.WriteAllText(
                requestPath,
                JsonSerializer.Serialize(request),
                new UTF8Encoding(false));

            var startInfo = new ProcessStartInfo(helper)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = $"--elevated-ipc \"{requestPath}\" \"{responsePath}\"",
            };

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                error = "无法启动提权助手。";
                return null;
            }

            if (!process.WaitForExit(120_000))
            {
                TryKill(process);
                error = "提权操作超时（120 秒）。";
                return null;
            }

            if (!File.Exists(responsePath))
            {
                error = $"提权操作失败（退出码 {process.ExitCode}）。";
                return null;
            }

            var response = JsonSerializer.Deserialize<ServiceResponse>(
                File.ReadAllText(responsePath, Encoding.UTF8));

            if (response is null)
            {
                error = "提权助手返回了空响应。";
                return null;
            }

            return response;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == UacCancelledError)
        {
            error = CancelledMessage;
            return null;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
        finally
        {
            TryDelete(requestPath);
            TryDelete(responsePath);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            process.Kill();
        }
        catch (Exception)
        {
            // 进程可能已经退出。
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception)
        {
            // 临时文件删不掉不影响结果。
        }
    }
}
