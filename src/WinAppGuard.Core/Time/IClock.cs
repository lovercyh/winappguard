namespace WinAppGuard.Core.Time;

/// <summary>5.9：可注入的时钟。冷却、TTL、去重都通过它读取当前时间，测试里可以瞬间推进。</summary>
public interface IClock
{
    DateTime UtcNow { get; }
}

/// <summary>生产环境使用的系统时钟。</summary>
public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();

    public DateTime UtcNow => DateTime.UtcNow;
}
