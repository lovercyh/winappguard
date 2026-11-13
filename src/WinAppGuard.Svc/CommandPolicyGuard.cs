using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Service;

/// <summary>
/// 5.9：命令权限判定的唯一入口。
///
/// 协议使用 ServiceRequest，响应是强类型 ResponsePayload；不再在 ControlServer 里
/// 用 "write." 前缀、alert 白名单和永久抑制特判三套机制分散判断。
/// </summary>
internal static class CommandPolicyGuard
{
    /// <summary>返回 null 表示允许继续执行；否则返回拒绝响应。</summary>
    internal static ResponsePayload? Check(
        ServiceRequest request,
        bool elevated,
        uint clientPid)
    {
        if (!CommandPolicyTable.TryGet(request.Command, out var policy))
        {
            // 未声明的命令按未知命令处理，不能默认当成只读放行。
            return new ErrorView
            {
                
                Ok = false,
                ErrorCode = "UnknownCommand",
                Error = $"未知命令：{request.Command}",
            };
        }

        switch (policy)
        {
            case CommandPolicy.Write when !elevated:
                ServiceLog.Warning(
                    "WAG-AUTH-005",
                    $"Rejected write operation: pid={clientPid} is not elevated, command={request.Command}.");

                return new ErrorView
                {
                    
                    Ok = false,
                    ErrorCode = "NotElevated",
                    Error = "修改规则需要管理员权限（请从界面操作，会弹出 UAC）。",
                };

            case CommandPolicy.AlertMetadata:
                ServiceLog.Operation(
                    "WAG-ALERT-001",
                    $"Alert command: {request.Command} (pid={clientPid}, elevated={elevated}).");
                break;

            case CommandPolicy.OwnerTemporaryWfp:
                ServiceLog.Operation(
                    "WAG-GUARD-000",
                    $"Temporary new-program command: {request.Command} (pid={clientPid}, elevated={elevated}).");
                break;
        }

        // “永久不再提醒”会长期改变检测可见性，即使走 alert.* 也要求管理员同意。
        if (ServiceProtocol.IsPermanentAlertSuppression(request) && !elevated)
        {
            return new ErrorView
            {
                
                Ok = false,
                ErrorCode = "NotElevated",
                Error = "永久不再提醒需要管理员权限。",
            };
        }

        return null;
    }
}
