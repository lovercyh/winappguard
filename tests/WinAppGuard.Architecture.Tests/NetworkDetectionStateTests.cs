using WinAppGuard.Core.Diagnostics.NetworkDetection;

namespace WinAppGuard.Architecture.Tests;

/// <summary>6.0：规则档位在状态文件往返后不能被改写。</summary>
public sealed class NetworkDetectionStateTests
{
    [Theory]
    [InlineData("curated", "curated")]
    [InlineData("standard", "standard")]
    [InlineData("full", "full")]
    [InlineData("", "curated")]
    [InlineData("unknown", "curated")]
    public void RuleProfileSurvivesRoundTrip(string saved, string expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"wag-nd-{Guid.NewGuid():N}.json");

        try
        {
            var state = new NetworkDetectionState();
            state.Settings.RuleProfile = saved;

            NetworkDetectionStateFile.Save(path, state);

            var loaded = NetworkDetectionStateFile.Load(path, out var error);

            Assert.Null(error);
            Assert.Equal(expected, loaded.Settings.RuleProfile);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
