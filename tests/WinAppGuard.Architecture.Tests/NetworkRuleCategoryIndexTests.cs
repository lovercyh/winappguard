using WinAppGuard.Core.Diagnostics.NetworkDetection;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.14：反网络攻击告警分类索引。
///
/// 告警只带 SID，设置里的分类来自规则文件；这里验证 SID 提取不会被
/// 注释或 content/pcre 里的 "sid:" 文本带偏。
/// </summary>
public sealed class NetworkRuleCategoryIndexTests
{
    [Theory]
    [InlineData(
        "alert tcp any any -> any any (msg:\"x\"; sid:2010935; rev:2;)",
        2010935L)]
    [InlineData(
        "alert dns any any -> any any (msg:\"x\"; classtype:bad-unknown; sid:2023883; rev:4;)",
        2023883L)]
    public void ParsesSidFromRuleLine(string line, long expected)
    {
        Assert.True(NetworkRuleCategoryIndex.TryParseSid(line, out var sid));
        Assert.Equal(expected, sid);
    }

    [Theory]
    [InlineData("# alert tcp any any -> any any (sid:1;)")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("alert tcp any any -> any any (msg:\"sid:123\"; sid:0;)")]
    [InlineData("alert tcp any any -> any any (msg:\"sid:123\" no real option)")]
    public void IgnoresCommentsAndNonRuleSids(string line)
    {
        Assert.False(NetworkRuleCategoryIndex.TryParseSid(line, out _));
    }

    [Fact]
    public void DoesNotMatchSidTextInsideContent()
    {
        // content 里出现 "sid:123" 时，前面没有规则选项分隔符，不能算 SID。
        const string line =
            "alert http any any -> any any (msg:\"x\"; content:\"sid:123\"; sid:2020001;)";

        Assert.True(NetworkRuleCategoryIndex.TryParseSid(line, out var sid));
        Assert.Equal(2020001, sid);
    }

    [Fact]
    public void DuplicateSidKeepsFirstCategory()
    {
        var map = new Dictionary<long, string>();

        var added = NetworkRuleCategoryIndex.IndexLines(
            NetworkRuleCategories.Malware,
            new[]
            {
                "alert tcp any any -> any any (msg:\"a\"; sid:100; rev:1;)",
                "alert tcp any any -> any any (msg:\"b\"; sid:100; rev:2;)",
            },
            map);

        Assert.Equal(1, added);
        Assert.Equal(NetworkRuleCategories.Malware, map[100]);
    }
}
