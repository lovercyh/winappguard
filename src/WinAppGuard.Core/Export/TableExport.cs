using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace WinAppGuard.Core.Export;

/// <summary>导出表格的一列：固定 key（给 JSON）和当前语言的表头（给 CSV）。</summary>
public sealed record TableExportColumn(string Key, string Header);

/// <summary>
/// 一份表格导出文档。
///
/// 设计原则：
///   - 只描述数据，不关心是哪个页面；
///   - JSON 用固定英文 key，方便脚本；
///   - CSV 用调用方给的表头，跟随界面语言；
///   - 所有值都只写本地文件，不联网。
/// </summary>
public sealed class TableExportDocument
{
    public string Format { get; init; } = TableExport.FormatName;

    public int Version { get; init; } = TableExport.CurrentVersion;

    public DateTime ExportedUtc { get; init; } = DateTime.UtcNow;

    /// <summary>生成该文件的程序版本；由调用方传入，Core 不依赖 WinForms。</summary>
    public string ToolVersion { get; init; } = string.Empty;

    /// <summary>视图名，例如 connections / audit / dns / network-alerts / traffic。</summary>
    public string View { get; init; } = string.Empty;

    public IReadOnlyList<TableExportColumn> Columns { get; init; } = Array.Empty<TableExportColumn>();

    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows { get; init; }
        = Array.Empty<IReadOnlyDictionary<string, object?>>();
}

/// <summary>
/// CSV / JSON 表格导出器 —— **纯本地文件写入，不联网**。
///
/// CSV 用 UTF-8 BOM + CRLF，Excel 双击打开中文不乱码；
/// 字段按 RFC 4180 转义：包含逗号、引号、换行的值加双引号，内部双引号写两遍。
/// </summary>
public static class TableExport
{
    public const string FormatName = "WinAppGuard.Table";
    public const int CurrentVersion = 1;

    private static readonly Encoding CsvEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

    /// <summary>生成 CSV 文本（不写文件，便于自检直接断言）。</summary>
    public static string ToCsv(TableExportDocument document)
    {
        var builder = new StringBuilder();

        for (var i = 0; i < document.Columns.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            builder.Append(EscapeCsv(document.Columns[i].Header));
        }

        builder.Append("\r\n");

        foreach (var row in document.Rows)
        {
            for (var i = 0; i < document.Columns.Count; i++)
            {
                if (i > 0)
                {
                    builder.Append(',');
                }

                var value = row.TryGetValue(document.Columns[i].Key, out var item)
                    ? FormatCsvValue(item)
                    : string.Empty;

                builder.Append(EscapeCsv(value));
            }

            builder.Append("\r\n");
        }

        return builder.ToString();
    }

    /// <summary>生成 JSON 文本（不写文件）。</summary>
    public static string ToJson(TableExportDocument document)
        => JsonSerializer.Serialize(document, JsonOptions);

    public static void WriteCsv(string path, TableExportDocument document)
        => File.WriteAllText(path, ToCsv(document), CsvEncoding);

    public static void WriteJson(string path, TableExportDocument document)
        => File.WriteAllText(path, ToJson(document), new UTF8Encoding(false));

    /// <summary>CSV 字段转义。空值输出空字符串；纯文本不额外加引号。</summary>
    public static string EscapeCsv(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var needsQuote = value.Contains(',')
                         || value.Contains('"')
                         || value.Contains('\r')
                         || value.Contains('\n')
                         || value[0] == ' '
                         || value[^1] == ' ';

        return needsQuote
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
    }

    private static string FormatCsvValue(object? value) => value switch
    {
        null => string.Empty,
        bool flag => flag ? "true" : "false",
        DateTime time => time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        DateTimeOffset time => time.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty,
        _ => value.ToString() ?? string.Empty,
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };
}
