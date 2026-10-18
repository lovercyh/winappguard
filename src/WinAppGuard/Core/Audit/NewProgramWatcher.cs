namespace WinAppGuard.Core.Audit;

/// <summary>
/// 新程序检测：把"第一次见到的程序"挑出来，交给界面去提示。
///
/// 分离成独立类的原因：告警的时机与"是否弹窗"是两件事 ——
///   - <b>学习模式</b>里仍然要记录（否则学不到东西），只是**不弹窗**；
///   - 用户选过"允许 / 忽略"之后，同一个程序**永远不再提示**。
/// 这两条都由这个类统一处理，界面只负责显示。
/// </summary>
internal sealed class NewProgramWatcher
{
    private readonly KnownProgramStore _store;

    internal NewProgramWatcher(KnownProgramStore store)
    {
        _store = store;
    }

    /// <summary>发现新程序（只在未抑制告警时触发）。</summary>
    internal event Action<string>? NewProgramDetected;

    /// <summary>
    /// 是否抑制告警（学习模式）。抑制时仍会记录，只是不触发事件。
    /// </summary>
    internal bool SuppressAlerts { get; set; }

    /// <summary>已知程序表（界面用它判断某个程序是否已有决定）。</summary>
    internal KnownProgramStore Store => _store;

    /// <summary>
    /// 观察一批程序路径。
    /// </summary>
    /// <returns>本次真正触发了告警的个数（学习模式或已见过时为 0）。</returns>
    internal int Observe(IEnumerable<string> processPaths, DateTime nowUtc)
    {
        var raised = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in processPaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !seen.Add(path))
            {
                continue;
            }

            var isNew = _store.Observe(path, nowUtc);

            if (isNew && !SuppressAlerts)
            {
                raised++;
                NewProgramDetected?.Invoke(path);
            }
        }

        return raised;
    }
}
