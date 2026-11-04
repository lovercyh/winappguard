using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.NetworkDetection;

/// <summary>
/// 5.0：只读 tail Suricata 的 eve.json。
///
/// 约定：
///   - 只处理 event_type=alert；stats 只更新计数，不进告警列表；
///   - 单行上限 1 MB，超长行丢弃并计数；
///   - 文件被轮转/截断时重新从头读；
///   - 启动时从文件末尾开始，避免把上次运行的历史告警再报一遍。
/// </summary>
internal sealed class EveAlertReader : IDisposable
{
    private const int MaxLineBytes = 1024 * 1024;
    private const int ReadChunkBytes = 256 * 1024;

    private readonly object _gate = new();
    private readonly string _path;
    private readonly Action<NetworkAlert> _onAlert;
    private readonly Action<string>? _onError;
    private readonly List<byte> _pending = new();
    private readonly System.Threading.Timer _timer;

    private FileStream? _stream;
    private long _offset;
    private bool _started;
    private bool _disposed;
    private long _eventsSeen;
    private long _eventsLost;

    internal EveAlertReader(
        string path,
        Action<NetworkAlert> onAlert,
        Action<string>? onError = null)
    {
        _path = path;
        _onAlert = onAlert;
        _onError = onError;
        _timer = new System.Threading.Timer(_ => Tick(), null, Timeout.Infinite, Timeout.Infinite);
    }

    internal long EventsSeen => Interlocked.Read(ref _eventsSeen);

    internal long EventsLost => Interlocked.Read(ref _eventsLost);

    internal void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }

            _started = true;
            _pending.Clear();
            _offset = TryGetLength();
            _timer.Change(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        }
    }

    internal void Stop()
    {
        lock (_gate)
        {
            _started = false;
            _timer.Change(Timeout.Infinite, Timeout.Infinite);
            _stream?.Dispose();
            _stream = null;
            _pending.Clear();
        }
    }

    private void Tick()
    {
        try
        {
            lock (_gate)
            {
                if (!_started || _disposed)
                {
                    return;
                }

                ReadNewData();
            }
        }
        catch (Exception ex)
        {
            _onError?.Invoke($"读取 eve.json 失败：{ex.Message}");
        }
    }

    private void ReadNewData()
    {
        if (!File.Exists(_path))
        {
            _stream?.Dispose();
            _stream = null;
            _offset = 0;
            _pending.Clear();
            return;
        }

        var length = TryGetLength();

        if (length < _offset)
        {
            // 轮转/截断：旧句柄可能指向已被替换的文件，必须重新打开。
            _stream?.Dispose();
            _stream = null;
            _offset = 0;
            _pending.Clear();
        }

        if (length == _offset)
        {
            return;
        }

        _stream ??= new FileStream(
            _path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);

        _stream.Seek(_offset, SeekOrigin.Begin);

        while (_offset < length)
        {
            var want = (int)Math.Min(ReadChunkBytes, length - _offset);
            var buffer = new byte[want];
            var read = _stream.Read(buffer, 0, want);

            if (read <= 0)
            {
                break;
            }

            _offset += read;
            AppendBytes(buffer, read);
        }
    }

    private void AppendBytes(byte[] buffer, int count)
    {
        for (var i = 0; i < count; i++)
        {
            var value = buffer[i];

            if (value == (byte)'\n')
            {
                ProcessLine();
                continue;
            }

            _pending.Add(value);

            if (_pending.Count > MaxLineBytes)
            {
                _pending.Clear();
                Interlocked.Increment(ref _eventsLost);
            }
        }
    }

    private void ProcessLine()
    {
        if (_pending.Count == 0)
        {
            return;
        }

        var bytes = _pending.ToArray();
        _pending.Clear();

        if (bytes.Length > 0 && bytes[^1] == (byte)'\r')
        {
            Array.Resize(ref bytes, bytes.Length - 1);
        }

        if (bytes.Length == 0)
        {
            return;
        }

        Interlocked.Increment(ref _eventsSeen);

        try
        {
            var line = Encoding.UTF8.GetString(bytes);
            var alert = Parse(line);

            if (alert is not null)
            {
                _onAlert(alert);
            }
        }
        catch (Exception)
        {
            Interlocked.Increment(ref _eventsLost);
        }
    }

    internal static NetworkAlert? Parse(string line)
    {
        using var document = JsonDocument.Parse(line);

        if (!document.RootElement.TryGetProperty("event_type", out var eventType)
            || !string.Equals(eventType.GetString(), "alert", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var root = document.RootElement;
        var alertNode = root.TryGetProperty("alert", out var alertElement)
            ? alertElement
            : default;

        if (alertNode.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var signature = GetString(alertNode, "signature") ?? "未命名规则";
        var signatureId = GetInt64(alertNode, "signature_id");
        var category = GetString(alertNode, "category") ?? string.Empty;
        var severityNumber = GetInt32(alertNode, "severity");
        var severity = severityNumber switch
        {
            1 => "high",
            2 => "medium",
            3 => "low",
            _ => "low",
        };

        var time = GetTime(root, "timestamp");
        var srcAddress = GetString(root, "src_ip") ?? string.Empty;
        var destAddress = GetString(root, "dest_ip") ?? string.Empty;
        var srcPort = GetInt32(root, "src_port");
        var destPort = GetInt32(root, "dest_port");
        var protocol = GetString(root, "proto") ?? string.Empty;
        var appProto = GetString(root, "app_proto") ?? string.Empty;
        var flowId = GetInt64(root, "flow_id");

        var (pid, processName, processPath) = FlowProcessResolver.Resolve(
            protocol, srcAddress, srcPort, destAddress, destPort);

        var evidence = BuildEvidence(root);

        return new NetworkAlert
        {
            TimeUtc = time,
            SignatureId = signatureId,
            Signature = signature,
            Severity = severity,
            Category = category,
            Protocol = protocol,
            AppProto = appProto,
            LocalAddress = srcAddress,
            LocalPort = srcPort,
            RemoteAddress = destAddress,
            RemotePort = destPort,
            Pid = pid,
            ProcessName = processName,
            ProcessPath = string.IsNullOrEmpty(processPath) ? null : processPath,
            FlowId = flowId,
            Evidence = evidence,
        };
    }

    private static string BuildEvidence(JsonElement root)
    {
        var parts = new List<string>();

        if (root.TryGetProperty("http", out var http) && http.ValueKind == JsonValueKind.Object)
        {
            var host = GetString(http, "hostname");
            var url = GetString(http, "url");
            var method = GetString(http, "http_method");
            var agent = GetString(http, "http_user_agent");

            if (!string.IsNullOrEmpty(method) || !string.IsNullOrEmpty(url))
            {
                parts.Add($"{method} {host}{url}".Trim());
            }
            else if (!string.IsNullOrEmpty(host))
            {
                parts.Add($"HTTP Host: {host}");
            }

            if (!string.IsNullOrEmpty(agent))
            {
                parts.Add($"UA: {Truncate(agent, 120)}");
            }
        }

        if (root.TryGetProperty("dns", out var dns) && dns.ValueKind == JsonValueKind.Object)
        {
            var names = new List<string>();

            if (dns.TryGetProperty("query", out var query))
            {
                if (query.ValueKind == JsonValueKind.Array)
                {
                    names.AddRange(query.EnumerateArray()
                        .Select(item => item.GetString())
                        .Where(item => !string.IsNullOrWhiteSpace(item))
                        .Take(3)!);
                }
                else
                {
                    var text = query.GetString();
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        names.Add(text);
                    }
                }
            }

            // Suricata 8 的 alert 事件使用 queries[].rrname。
            if (dns.TryGetProperty("queries", out var queries)
                && queries.ValueKind == JsonValueKind.Array)
            {
                names.AddRange(queries.EnumerateArray()
                    .Select(item => item.TryGetProperty("rrname", out var rrname)
                        ? rrname.GetString()
                        : null)
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Take(3)!);
            }

            var dnsText = string.Join(", ", names.Distinct(StringComparer.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(dnsText))
            {
                parts.Add($"DNS: {dnsText}");
            }
        }

        if (root.TryGetProperty("tls", out var tls) && tls.ValueKind == JsonValueKind.Object)
        {
            var sni = GetString(tls, "sni");
            if (!string.IsNullOrWhiteSpace(sni))
            {
                parts.Add($"TLS SNI: {sni}");
            }
        }

        // 默认配置里 payload=no；只有用户显式打开时才可能出现。
        var payload = GetString(root, "payload_printable");
        if (!string.IsNullOrWhiteSpace(payload))
        {
            parts.Add($"payload: {Truncate(payload, 200)}");
        }

        return Truncate(string.Join("; ", parts), 512);
    }

    private static DateTime GetTime(JsonElement root, string name)
    {
        var text = GetString(root, name);

        return DateTime.TryParse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out var value)
            ? value
            : DateTime.UtcNow;
    }

    private static string? GetString(JsonElement element, string name)
        => element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int GetInt32(JsonElement element, string name)
        => element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var result)
            ? result
            : 0;

    private static long GetInt64(JsonElement element, string name)
        => element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt64(out var result)
            ? result
            : 0;

    private static string Truncate(string text, int max)
    {
        var normalized = text
            .Replace('\r', ' ')
            .Replace('\n', ' ');

        return normalized.Length <= max
            ? normalized
            : normalized[..max] + "…";
    }

    private long TryGetLength()
    {
        try
        {
            return File.Exists(_path) ? new FileInfo(_path).Length : 0;
        }
        catch (Exception)
        {
            return 0;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Stop();
        _timer.Dispose();
    }
}
