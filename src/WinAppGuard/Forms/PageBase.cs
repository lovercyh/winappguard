namespace WinAppGuard.Forms;

/// <summary>
/// 5.9：一个可见页的刷新描述。
///
/// 页面只声明“何时可见 / 是否启用自动刷新 / 刷新做什么”，
/// 具体的定时、去重、异常隔离由 <see cref="UiRefreshScheduler"/> 统一处理。
/// </summary>
internal abstract class PageBase
{
    protected PageBase(string key, int intervalMs)
    {
        Key = key;
        IntervalMs = intervalMs;
    }

    internal string Key { get; }

    internal int IntervalMs { get; }

    /// <summary>页面当前是否对用户可见。不可见时不做任何刷新。</summary>
    internal abstract bool IsVisible { get; }

    /// <summary>页面自己的“自动刷新”开关；默认开启。</summary>
    internal virtual bool IsAutoRefreshEnabled => true;

    internal abstract Task RefreshAsync();

    internal void Register(UiRefreshScheduler scheduler)
        => scheduler.Register(
            Key,
            IntervalMs,
            () => IsAutoRefreshEnabled && IsVisible,
            RefreshAsync);
}
