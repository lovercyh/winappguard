using WinAppGuard.Service;

namespace WinAppGuard.Architecture.Tests;

/// <summary>6.0：三个规则档位都附加 ThreatFox 规则，档位决定置信度门槛。</summary>
public sealed class ThreatFoxRuleProfileTests
{
    [Theory]
    [InlineData("curated", 100)]
    [InlineData("standard", 90)]
    [InlineData("full", 0)]
    public void ThresholdFollowsProfile(string profile, int expected)
        => Assert.Equal(expected, SuricataHost.ThreatFoxThreshold(profile));

    [Fact]
    public void BundledRulesMatchDocumentedCounts()
    {
        var path = FindRepoFile(Path.Combine("threatfox", "threatfox_suricata.rules"));

        if (path is null)
        {
            return;
        }

        Assert.Equal(80_412, SuricataHost.CountThreatFoxRules(path, 0));
        Assert.Equal(42_273, SuricataHost.CountThreatFoxRules(path, 90));
        Assert.Equal(35_843, SuricataHost.CountThreatFoxRules(path, 100));
    }

    private static string? FindRepoFile(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        for (var i = 0; i < 8 && directory is not null; i++)
        {
            var candidate = Path.Combine(directory.FullName, relativePath);

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
