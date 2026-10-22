using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 提权 IPC 助手（3.0-c）：界面以普通权限运行时，用 <c>runas</c> 启动本进程执行一条写命令。
///
/// 只接受 `write.*` 命令，响应写回界面给的临时文件。
/// 这样界面永远不需要管理员权限，但每次改规则都会弹一次 UAC（M1.5）。
/// </summary>
internal static class ElevatedIpc
{
    internal static int Run(string[] args)
    {
        if (!AdminHelper.IsRunningAsAdmin())
        {
            return 3;
        }

        var index = Array.FindIndex(
            args, arg => arg.Equals("--elevated-ipc", StringComparison.OrdinalIgnoreCase));

        if (index < 0 || index + 2 >= args.Length)
        {
            return 1;
        }

        var requestPath = args[index + 1];
        var responsePath = args[index + 2];

        ServiceResponse response;

        try
        {
            var request = JsonSerializer.Deserialize<ServiceRequest>(
                File.ReadAllText(requestPath, Encoding.UTF8));

            if (request is null
                || !request.Command.StartsWith("write.", StringComparison.OrdinalIgnoreCase))
            {
                response = new ServiceResponse
                {
                    Ok = false,
                    Error = "提权助手只接受写命令。",
                };
            }
            else
            {
                response = ServiceClient.TryRequest(
                    request, TimeSpan.FromSeconds(15), out var error)
                    ?? new ServiceResponse
                    {
                        Ok = false,
                        Error = $"防护服务没有响应：{error}",
                    };
            }
        }
        catch (Exception ex)
        {
            response = new ServiceResponse { Ok = false, Error = ex.Message };
        }

        try
        {
            File.WriteAllText(
                responsePath,
                JsonSerializer.Serialize(response),
                new UTF8Encoding(false));
        }
        catch (Exception)
        {
            return 2;
        }

        return response.Ok ? 0 : 2;
    }
}
