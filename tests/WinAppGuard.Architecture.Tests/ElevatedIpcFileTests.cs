using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;
using WinAppGuard.Core;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.13.1：提权助手的临时文件必须和界面用同一套 JSON 选项读写。
///
/// 回归的是“显示 0 条”：助手写 camelCase（affected），界面用默认选项按
/// PascalCase 读，Affected / Skipped / Failed / Error 全部丢失，只剩默认 Ok=true。
/// </summary>
public sealed class ElevatedIpcFileTests
{
    [Fact]
    public void ResponseFileKeepsBatchCounts()
    {
        var path = TempFile();

        try
        {
            ElevatedIpcFile.WriteResponse(path, new WriteResult
            {
                Ok = true,
                Affected = 7,
                Skipped = 2,
                Failed = 1,
            });

            // 助手写出的必须是 camelCase；界面读回必须还能拿到值。
            var text = File.ReadAllText(path);
            Assert.Contains("\"affected\":7", text, StringComparison.Ordinal);

            var back = Assert.IsType<WriteResult>(
                ElevatedIpcFile.ReadResponse(path, typeof(WriteResult)));

            Assert.True(back.Ok);
            Assert.Equal(7, back.Affected);
            Assert.Equal(2, back.Skipped);
            Assert.Equal(1, back.Failed);
        }
        finally
        {
            TryDelete(path);
        }
    }

    [Fact]
    public void ResponseFileKeepsErrorText()
    {
        var path = TempFile();

        try
        {
            ElevatedIpcFile.WriteResponse(path, new WriteResult
            {
                Ok = false,
                Error = "导入失败：规则文件不认识。",
            });

            var back = Assert.IsType<WriteResult>(
                ElevatedIpcFile.ReadResponse(path, typeof(WriteResult)));

            Assert.False(back.Ok);
            Assert.Equal("导入失败：规则文件不认识。", back.Error);
        }
        finally
        {
            TryDelete(path);
        }
    }

    [Fact]
    public void RequestFileKeepsActionAndJson()
    {
        var path = TempFile();

        try
        {
            ElevatedIpcFile.WriteRequest(path, new ServiceRequest
            {
                Command = ServiceProtocol.Commands.ImportRules,
                Action = "allow",
                Json = "{\"Rules\":[]}",
            });

            var back = ElevatedIpcFile.ReadRequest(path);

            Assert.NotNull(back);
            Assert.Equal(ServiceProtocol.Commands.ImportRules, back!.Command);
            Assert.Equal("allow", back.Action);
            Assert.Equal("{\"Rules\":[]}", back.Json);
        }
        finally
        {
            TryDelete(path);
        }
    }

    private static string TempFile()
        => Path.Combine(
            Path.GetTempPath(), $"wag-elevated-test-{Guid.NewGuid():N}.json");

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // 临时文件删不掉不影响测试结论。
        }
    }
}
