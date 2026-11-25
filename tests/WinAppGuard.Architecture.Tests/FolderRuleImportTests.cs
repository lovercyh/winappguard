using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.13：文件夹批量添加走的是现有的导入文档格式。
/// 这里验证 UI 组装的文档能被服务端解析并通过 block/allow 校验。
/// </summary>
public sealed class FolderRuleImportTests
{
    [Theory]
    [InlineData(FirewallAction.Block, "block")]
    [InlineData(FirewallAction.Allow, "allow")]
    public void FolderImportDocumentRoundTrips(FirewallAction action, string scope)
    {
        var document = new RuleExportDocument { Scope = scope };

        document.Rules.Add(new RuleExportEntry
        {
            Kind = "program",
            Value = @"C:\Tools\a.exe",
            Action = scope,
            Expiry = string.Empty,
            Group = "folder: Tools",
            Scope = string.Empty,
        });

        var json = RuleExport.Serialize(document);

        Assert.True(RuleExport.TryParse(json, out var parsed, out var parseError), parseError);
        Assert.NotNull(parsed);
        Assert.True(RuleExport.TryMatchScope(parsed!, action, out var scopeError), scopeError);
        Assert.Single(parsed!.Rules);
        Assert.Equal(@"C:\Tools\a.exe", parsed.Rules[0].Value);
        Assert.Equal(scope, parsed.Rules[0].Action);
        Assert.Equal("folder: Tools", parsed.Rules[0].Group);
    }
}
