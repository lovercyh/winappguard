using System.Reflection;

namespace WinAppGuard.Contracts;

/// <summary>
/// 5.9：命令权限策略。
///
/// 与现有实现的关键差别：
///   - 不再靠命令名前缀或散落的 if 判断；
///   - 新命令没有声明策略时，路由/测试会直接失败；
///   - 5.8 的 guard.new-program.* 是独立策略，不能归入 Read / Write / Alert。
/// </summary>
public enum CommandPolicy
{
    /// <summary>只读查询，所有者签名即可，不提权。</summary>
    Read = 0,

    /// <summary>普通系统变更，需要管理员提权（现有 write. 命令）。</summary>
    Write = 1,

    /// <summary>只改告警元数据，所有者签名即可，不提权（现有 alert.* 命令）。</summary>
    AlertMetadata = 2,

    /// <summary>
    /// 5.8 的例外：所有者签名、不提权，但创建临时 WFP 过滤器。
    /// 只允许 guard.new-program.block / guard.new-program.release。
    /// </summary>
    OwnerTemporaryWfp = 3,
}

/// <summary>
/// 5.9：显式命令策略表。
///
/// 现在从 <see cref="ServiceProtocol.Commands"/> 的常量反射生成，保证“每个已声明命令
/// 都有策略”；协议 v3 / CommandRouter 接入后，这份表会变成 Handler 注册的一部分。
/// 不引入 DI 容器或运行时反射扫描业务代码。
/// </summary>
public static class CommandPolicyTable
{
    private static readonly IReadOnlyDictionary<string, CommandPolicy> Policies = Build();

    public static IReadOnlyDictionary<string, CommandPolicy> All => Policies;

    public static CommandPolicy Get(string command)
        => Policies.TryGetValue(command, out var policy)
            ? policy
            : throw new InvalidOperationException($"命令没有声明权限策略：{command}");

    public static bool TryGet(string command, out CommandPolicy policy)
        => Policies.TryGetValue(command, out policy);

    /// <summary>5.8：只有这两个命令允许 OwnerTemporaryWfp。</summary>
    public static bool IsNewProgramGuardCommand(string command)
        => string.Equals(command, ServiceProtocol.Commands.GuardNewProgramBlock, StringComparison.Ordinal)
           || string.Equals(command, ServiceProtocol.Commands.GuardNewProgramRelease, StringComparison.Ordinal);

    /// <summary>5.9：协议声明的全部命令。路由和测试都从这里取，避免各自反射。</summary>
    public static IReadOnlyList<string> DeclaredCommands()
        => typeof(ServiceProtocol.Commands)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string?)field.GetRawConstantValue())
            .Where(command => !string.IsNullOrWhiteSpace(command))
            .Select(command => command!)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(command => command, StringComparer.Ordinal)
            .ToList();

    private static IReadOnlyDictionary<string, CommandPolicy> Build()
    {
        var policies = new Dictionary<string, CommandPolicy>(StringComparer.Ordinal);

        foreach (var command in DeclaredCommands())
        {
            policies[command] = Classify(command);
        }

        return policies;
    }

    private static CommandPolicy Classify(string command)
    {
        if (IsNewProgramGuardCommand(command))
        {
            return CommandPolicy.OwnerTemporaryWfp;
        }

        if (command.StartsWith("write.", StringComparison.OrdinalIgnoreCase))
        {
            return CommandPolicy.Write;
        }

        if (command.StartsWith("alert.", StringComparison.OrdinalIgnoreCase))
        {
            return CommandPolicy.AlertMetadata;
        }

        return CommandPolicy.Read;
    }
}
