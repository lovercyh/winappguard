using System.Collections;
using System.Reflection;
using WinAppGuard.Contracts;
using WinAppGuard.Core.Audit;
using WinAppGuard.Core.Export;
using WinAppGuard.Models;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>
/// 5.7：诊断包里的 CSV 生成器。
///
/// 诊断包默认提供可直接用 Excel 打开的 CSV；服务原始响应仍保留在 data/raw 里，
/// 需要看嵌套字段或完整结构时再用 JSON。
///
/// 服务事件 DTO 用反射列属性，避免每加一个字段就要在诊断包里补一次列名；
/// 连接行则手写列，因为 TcpConnectionItem 还带界面用的计算属性和对象属性，
/// 直接反射会把 Signature / IpOwnership 这类复合对象塞进来。
/// </summary>
internal static class DiagnosticCsv
{
    public static string Connections(IEnumerable<TcpConnectionItem> items)
    {
        var columns = new[]
        {
            new TableExportColumn("processName", "processName"),
            new TableExportColumn("processPath", "processPath"),
            new TableExportColumn("pid", "pid"),
            new TableExportColumn("protocol", "protocol"),
            new TableExportColumn("localPort", "localPort"),
            new TableExportColumn("remoteAddress", "remoteAddress"),
            new TableExportColumn("remotePort", "remotePort"),
            new TableExportColumn("state", "state"),
            new TableExportColumn("trafficOutBytes", "trafficOutBytes"),
            new TableExportColumn("trafficInBytes", "trafficInBytes"),
            new TableExportColumn("blocked", "blocked"),
            new TableExportColumn("whitelist", "whitelist"),
            new TableExportColumn("signatureState", "signatureState"),
            new TableExportColumn("signer", "signer"),
        };

        var rows = items.Select(item => Row(
            ("processName", item.ProcessName),
            ("processPath", item.ProcessPath),
            ("pid", item.Pid),
            ("protocol", item.Protocol),
            ("localPort", item.LocalPort),
            ("remoteAddress", item.RemoteAddressText),
            ("remotePort", item.RemotePort),
            ("state", item.State.ToString()),
            ("trafficOutBytes", item.TrafficBytesOut),
            ("trafficInBytes", item.TrafficBytesIn),
            ("blocked", item.IsBlocked),
            ("whitelist", item.Whitelist.ToString()),
            ("signatureState", item.Signature.State.ToString()),
            ("signer", item.Signature.SignerName)))
            .ToList();

        return Build("connections", columns, rows);
    }

    public static string FromObjects<T>(string view, IEnumerable<T>? items)
    {
        var list = items?.ToList() ?? new List<T>();
        var properties = typeof(T)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.GetMethod is not null && property.GetIndexParameters().Length == 0)
            .ToArray();

        var columns = properties
            .Select(property => new TableExportColumn(property.Name, property.Name))
            .ToArray();

        var rows = list
            .Select(item =>
            {
                var row = new Dictionary<string, object?>(properties.Length, StringComparer.Ordinal);

                foreach (var property in properties)
                {
                    object? value = null;

                    try
                    {
                        value = property.GetValue(item);
                    }
                    catch (Exception)
                    {
                        // 单个属性读不出来不能让整个诊断包失败。
                    }

                    row[property.Name] = FormatValue(value);
                }

                return (IReadOnlyDictionary<string, object?>)row;
            })
            .ToList();

        return Build(view, columns, rows);
    }

    public static string Audit(IEnumerable<AuditEvent> events)
        => FromObjects("audit", events);

    private static string Build(
        string view,
        IReadOnlyList<TableExportColumn> columns,
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
        => TableExport.ToCsv(new TableExportDocument
        {
            View = view,
            Columns = columns,
            Rows = rows,
        });

    private static IReadOnlyDictionary<string, object?> Row(
        params (string Key, object? Value)[] values)
    {
        var row = new Dictionary<string, object?>(values.Length, StringComparer.Ordinal);

        foreach (var (key, value) in values)
        {
            row[key] = value;
        }

        return row;
    }

    private static string FormatValue(object? value) => value switch
    {
        null => string.Empty,
        string text => text,
        bool flag => flag ? "true" : "false",
        DateTime time => time.ToString("O"),
        DateTimeOffset time => time.ToString("O"),
        IEnumerable enumerable => string.Join(
            "; ",
            enumerable.Cast<object?>().Select(FormatValue)),
        _ => value.ToString() ?? string.Empty,
    };
}
