using WinAppGuard.Core.Storage;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.16：状态文件并发写必须串行，且临时文件不能共用固定名字。
/// </summary>
public sealed class JsonStateFileConcurrencyTests
{
    [Fact]
    public async Task ConcurrentSavesLeaveAValidStateFile()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "wag-state-concurrency-" + Guid.NewGuid().ToString("N"),
            "state.json");

        try
        {
            var first = new JsonStateFile<State>(path, 1);
            var second = new JsonStateFile<State>(path, 1);

            var tasks = Enumerable.Range(0, 8).Select(index => Task.Run(() =>
            {
                var writer = index % 2 == 0 ? first : second;
                writer.Save(new State { Value = index });
            }));

            await Task.WhenAll(tasks);

            var loaded = first.Load(out var error);

            Assert.Null(error);
            Assert.NotNull(loaded);
            Assert.InRange(loaded!.Value, 0, 7);
        }
        finally
        {
            try
            {
                var directory = Path.GetDirectoryName(path);
                if (directory is not null && Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 临时目录清理失败不影响测试结论。
            }
        }
    }

    private sealed class State
    {
        public int Value { get; set; }
    }
}
