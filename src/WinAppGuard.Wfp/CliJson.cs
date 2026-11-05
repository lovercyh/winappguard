using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinAppGuard.Core;

/// <summary>
/// 5.3：CLI 的 JSON 输出。
///
/// 约定：key 固定英文、带 schemaVersion，不输出本地化文本。
/// 这样脚本不会因为界面语言变化而坏掉。
/// </summary>
internal static class CliJson
{
    internal const int SchemaVersion = 1;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    internal static void WriteSuccess(object? data, string toolVersion, bool indented = false)
    {
        var payload = new Dictionary<string, object?>
        {
            ["schemaVersion"] = SchemaVersion,
            ["toolVersion"] = toolVersion,
            ["ok"] = true,
            ["data"] = data,
        };

        Console.WriteLine(JsonSerializer.Serialize(payload, WithIndent(indented)));
    }

    internal static void WriteError(string code, string message, bool indented = false)
    {
        var payload = new Dictionary<string, object?>
        {
            ["schemaVersion"] = SchemaVersion,
            ["ok"] = false,
            ["error"] = new Dictionary<string, object?>
            {
                ["code"] = code,
                ["message"] = message,
            },
        };

        Console.WriteLine(JsonSerializer.Serialize(payload, WithIndent(indented)));
    }

    private static JsonSerializerOptions WithIndent(bool indented)
        => indented
            ? new JsonSerializerOptions(Options) { WriteIndented = true }
            : Options;
}
