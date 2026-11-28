using System.Runtime.InteropServices;
using WinAppGuard.Core.Diagnostics;

namespace WinAppGuard.Core.Diagnostics.Processes;

/// <summary>
/// 6.0：Kernel-Process ETW 监控。默认开启，只订阅 Process keyword。
/// </summary>
internal sealed class ProcessEtwMonitor : IDisposable
{
    internal const string SessionName = "WinAppGuard-Process";

    // Microsoft-Windows-Kernel-Process
    private static readonly Guid ProviderId =
        new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    // WINEVENT_KEYWORD_PROCESS；不订阅 Thread / ImageLoad。
    private const ulong ProcessKeyword = 0x10;
    private const ushort ProcessStartEventId = 1;
    private const ushort ProcessStopEventId = 2;

    private readonly ProcessTable _table;
    private EtwRealtimeSession? _session;
    private long _eventsSeen;
    private long _parseFailures;
    private string? _lastError;
    private DateTime? _lastEventUtc;

    internal ProcessEtwMonitor(ProcessTable table)
    {
        _table = table;
    }

    internal bool IsRunning => _session?.IsRunning == true;

    internal long EventsSeen => Interlocked.Read(ref _eventsSeen);

    internal long ParseFailures => Interlocked.Read(ref _parseFailures);

    internal string? LastError => _lastError;

    internal DateTime? LastEventUtc => _lastEventUtc;

    internal bool Start()
    {
        try
        {
            _session = new EtwRealtimeSession(
                SessionName,
                Guid.NewGuid(),
                ProviderId,
                ProcessKeyword,
                OnEvent,
                level: 4);

            if (_session.Start())
            {
                _lastError = null;
                return true;
            }

            _lastError = _session.LastError;
            _session.Dispose();
            _session = null;
            return false;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            _session?.Dispose();
            _session = null;
            return false;
        }
    }

    internal void Stop()
    {
        _session?.Dispose();
        _session = null;
    }

    public void Dispose() => Stop();

    private void OnEvent(IntPtr recordPointer)
    {
        try
        {
            var record = EtwRealtimeSession.ReadRecord(recordPointer);
            var data = record.UserData;
            var length = record.UserDataLength;

            if (data == IntPtr.Zero || length < 8)
            {
                return;
            }

            var timestamp = ToUtc(record.EventHeader.TimeStamp);

            if (record.EventHeader.Id == ProcessStopEventId)
            {
                var pid = Marshal.ReadInt32(data, 0);

                if (pid > 0)
                {
                    _table.AddStop(pid, timestamp);
                    Interlocked.Increment(ref _eventsSeen);
                    _lastEventUtc = timestamp;
                }

                return;
            }

            // ProcessStart 以及可能的 Rundown 事件都按同一模板解析；
            // Thread / ImageLoad 没有这两段字符串，会在这里被忽略。
            var offset = 8;
            var imagePath = ReadUtf16(data, length, ref offset);

            if (string.IsNullOrWhiteSpace(imagePath))
            {
                return;
            }

            var commandLine = ReadUtf16(data, length, ref offset);
            var pidStart = Marshal.ReadInt32(data, 0);
            var parentPid = Marshal.ReadInt32(data, 4);

            if (pidStart <= 0)
            {
                return;
            }

            _table.AddStart(new ProcessTraceEntry
            {
                Pid = pidStart,
                ParentPid = parentPid,
                ImagePath = imagePath,
                CommandLine = commandLine,
                ServiceInstance = ParseServiceInstance(imagePath, commandLine),
                LolbinRule = LolbinMatcher.Match(imagePath, commandLine),
                StartUtc = timestamp,
            });

            Interlocked.Increment(ref _eventsSeen);
            _lastEventUtc = timestamp;
        }
        catch (Exception)
        {
            Interlocked.Increment(ref _parseFailures);
        }
    }

    private static string ReadUtf16(IntPtr data, int length, ref int offset)
    {
        var builder = new System.Text.StringBuilder(260);
        var maxChars = Math.Min(4096, Math.Max(0, (length - offset) / 2));

        for (var i = 0; i < maxChars; i++)
        {
            var ch = (char)Marshal.ReadInt16(data, offset);
            offset += 2;

            if (ch == '\0')
            {
                break;
            }

            builder.Append(ch);
        }

        return builder.ToString();
    }

    private static string ParseServiceInstance(string imagePath, string commandLine)
    {
        if (!Path.GetFileName(imagePath).Equals(
                "svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var index = commandLine.IndexOf("-s ", StringComparison.OrdinalIgnoreCase);

        if (index < 0)
        {
            return string.Empty;
        }

        var rest = commandLine[(index + 3)..].Trim();

        if (rest.Length == 0)
        {
            return string.Empty;
        }

        var end = rest.IndexOf(' ');

        return end < 0 ? rest : rest[..end];
    }

    private static DateTime ToUtc(long timestamp)
    {
        // ETW 的 TimeStamp 通常是 FILETIME；不可信时退回当前时间。
        if (timestamp > 116444736000000000L && timestamp < 2650467743999999999L)
        {
            try
            {
                return DateTime.FromFileTimeUtc(timestamp);
            }
            catch (Exception)
            {
                // fall through
            }
        }

        return DateTime.UtcNow;
    }
}
