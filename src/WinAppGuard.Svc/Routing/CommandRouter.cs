using WinAppGuard.Contracts;

namespace WinAppGuard.Service;

/// <summary>
/// 5.9：每条命令执行时需要的上下文。
///
/// 协议仍是 v2 的 <see cref="ServiceRequest"/>/<see cref="ServiceResponse"/>；
/// 这里只把“请求 + 客户端令牌结果”打包，避免 Handler 再各自去猜提权状态。
/// </summary>
public readonly record struct CommandContext(
    ServiceRequest Request,
    bool Elevated,
    uint ClientPid);

/// <summary>
/// 5.9：一条命令一个 Handler。
///
/// <see cref="Module"/> 用于诊断和一致性校验（同一模块的命令应集中注册），
/// 不参与权限判定；权限只由 <see cref="CommandPolicyTable"/> 决定。
/// </summary>
public interface ICommandHandler
{
    string Command { get; }

    string Module { get; }

    ServiceResponse Handle(CommandContext context);
}

/// <summary>5.9：把委托包装成 Handler，避免为 70 多条命令各写一个类。</summary>
public sealed class DelegateCommandHandler : ICommandHandler
{
    private readonly Func<CommandContext, ServiceResponse> _handler;

    public DelegateCommandHandler(
        string command,
        string module,
        Func<CommandContext, ServiceResponse> handler)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            throw new ArgumentException("命令名不能为空。", nameof(command));
        }

        if (string.IsNullOrWhiteSpace(module))
        {
            throw new ArgumentException("模块名不能为空。", nameof(module));
        }

        Command = command;
        Module = module;
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    public string Command { get; }

    public string Module { get; }

    public ServiceResponse Handle(CommandContext context) => _handler(context);
}

/// <summary>
/// 5.9：命令路由。
///
/// 取代 <c>ControlServer</c> 里的大 switch：
///   - 注册重复命令直接失败；
///   - 启动期 <see cref="Validate"/> 保证“已声明的命令恰好一个 Handler”；
///   - 未注册的命令不会被默认当成只读执行。
///
/// 不引入 DI 容器，也不在运行时扫描业务程序集。
/// </summary>
public sealed class CommandRouter
{
    private readonly Dictionary<string, ICommandHandler> _handlers = new(StringComparer.Ordinal);

    public void Register(ICommandHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        if (!_handlers.TryAdd(handler.Command, handler))
        {
            throw new InvalidOperationException(
                $"命令被重复注册：{handler.Command}（已有模块 {_handlers[handler.Command].Module}，"
                + $"新模块 {handler.Module}）。");
        }
    }

    public bool TryGet(string command, out ICommandHandler handler)
        => _handlers.TryGetValue(command, out handler!);

    public IReadOnlyList<ICommandHandler> Handlers
        => _handlers.Values
            .OrderBy(handler => handler.Module, StringComparer.Ordinal)
            .ThenBy(handler => handler.Command, StringComparer.Ordinal)
            .ToList();

    public ServiceResponse Dispatch(CommandContext context)
    {
        if (!_handlers.TryGetValue(context.Request.Command, out var handler))
        {
            return new ServiceResponse
            {
                Id = context.Request.Id,
                Ok = false,
                Error = $"未知命令：{context.Request.Command}",
            };
        }

        return handler.Handle(context);
    }

    /// <summary>
    /// 启动期一致性校验。任何一条不满足都在启动时失败，而不是等到用户点到那条命令。
    /// </summary>
    public void Validate()
    {
        var declared = CommandPolicyTable.DeclaredCommands();

        foreach (var command in declared)
        {
            if (!_handlers.ContainsKey(command))
            {
                throw new InvalidOperationException($"命令没有注册 Handler：{command}");
            }

            if (!CommandPolicyTable.TryGet(command, out _))
            {
                throw new InvalidOperationException($"命令没有声明权限策略：{command}");
            }
        }

        var declaredSet = new HashSet<string>(declared, StringComparer.Ordinal);

        foreach (var handler in _handlers.Values)
        {
            if (!declaredSet.Contains(handler.Command))
            {
                throw new InvalidOperationException(
                    $"Handler 注册了未声明的命令：{handler.Command}（模块 {handler.Module}）。");
            }

            if (string.IsNullOrWhiteSpace(handler.Module))
            {
                throw new InvalidOperationException($"命令没有声明所属模块：{handler.Command}");
            }

            if (CommandPolicyTable.Get(handler.Command) == CommandPolicy.OwnerTemporaryWfp
                && !CommandPolicyTable.IsNewProgramGuardCommand(handler.Command))
            {
                throw new InvalidOperationException(
                    $"只有新程序提醒命令允许 OwnerTemporaryWfp：{handler.Command}");
            }
        }
    }
}
