using System.Net;
using System.Runtime.InteropServices;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Audit;

/// <summary>一条"被拦掉的连接"（来自 WFP 网络事件）。</summary>
internal sealed record WfpDropEvent(
    DateTime TimeUtc,
    string ProcessPath,
    string RemoteAddress,
    ushort RemotePort,
    byte Protocol,
    ulong FilterId,
    ushort LayerId);

/// <summary>
/// 订阅 WFP 的 **CLASSIFY_DROP** 网络事件 —— 这是"被哪条规则拦的"唯一可靠来源：
/// 轮询连接表根本看不到被拦的连接（它们从来没建立成功过）。
///
/// 布局与解析逻辑在 2.1 的 POC 里已经实测：
///   - 事件里有进程身份、真实的本地/远端 IP 与端口；
///   - `EventData` 指向 `FWPM_NET_EVENT_CLASSIFY_DROP1`（filterId + layerId）。
///
/// 只应在有管理员权限的进程里启动（打开引擎需要）。
/// </summary>
internal sealed class WfpDropCollector : IDisposable
{
    private readonly IntPtr _engine;
    private IntPtr _subscription;
    private WfpNetEventNative.NetEventCallback? _callback;
    private bool _disposed;

    private WfpDropCollector(IntPtr engine)
    {
        _engine = engine;
    }

    /// <summary>收到一条拦截事件。回调在 WFP 的线程上触发，订阅方自己注意线程安全。</summary>
    internal event Action<WfpDropEvent>? DropDetected;

    internal static WfpDropCollector Start()
    {
        WfpNetEventNative.EnsureLayout();

        var sessionKey = Guid.NewGuid();
        var session = new WfpNativeMethods.FwpmSession { SessionKey = sessionKey };

        var rc = WfpNativeMethods.FwpmEngineOpen0(
            null,
            WfpNativeMethods.RPC_C_AUTHN_WINNT,
            IntPtr.Zero,
            ref session,
            out var engine);

        if (rc != WfpNativeMethods.ERROR_SUCCESS)
        {
            throw new WfpException("打开 WFP 引擎（网络事件）", rc);
        }

        var collector = new WfpDropCollector(engine);

        try
        {
            collector.Subscribe(sessionKey);
            return collector;
        }
        catch
        {
            collector.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_subscription != IntPtr.Zero)
        {
            WfpNetEventNative.FwpmNetEventUnsubscribe0(_engine, _subscription);
            _subscription = IntPtr.Zero;
        }

        WfpNativeMethods.FwpmEngineClose0(_engine);
        _callback = null;
    }

    private void Subscribe(Guid sessionKey)
    {
        _callback = OnNetEvent;

        var subscription = new WfpNetEventNative.FwpmNetEventSubscription
        {
            EnumTemplate = IntPtr.Zero,
            Flags = 0,
            SessionKey = sessionKey,
        };

        var rc = WfpNetEventNative.FwpmNetEventSubscribe0(
            _engine,
            ref subscription,
            _callback,
            IntPtr.Zero,
            out _subscription);

        if (rc != WfpNativeMethods.ERROR_SUCCESS)
        {
            throw new WfpException("订阅 WFP 网络事件", rc);
        }
    }

    private void OnNetEvent(IntPtr context, IntPtr eventPtr)
    {
        try
        {
            var raw = Marshal.PtrToStructure<WfpNetEventNative.FwpmNetEvent1>(eventPtr);

            if (raw.Type != WfpNetEventNative.EventTypeClassifyDrop)
            {
                return;
            }

            var header = raw.Header;

            var filterId = 0UL;
            var layerId = (ushort)0;

            if (raw.EventData != IntPtr.Zero)
            {
                filterId = (ulong)Marshal.ReadInt64(raw.EventData);
                layerId = (ushort)Marshal.ReadInt16(raw.EventData, 8);
            }

            var drop = new WfpDropEvent(
                DateTime.FromFileTimeUtc(header.TimeStamp),
                DevicePathMapper.ToDosPath(ReadAppId(header.AppId)),
                FormatAddress(header.RemoteAddr, header.IpVersion),
                header.RemotePort,
                header.IpProtocol,
                filterId,
                layerId);

            DropDetected?.Invoke(drop);
        }
        catch (Exception)
        {
            // 事件解析失败不能影响订阅本身（更不能让审计把主功能拖垮）。
        }
    }

    private static string ReadAppId(WfpNativeMethods.FwpByteBlob blob)
    {
        if (blob.Size == 0 || blob.Data == IntPtr.Zero)
        {
            return string.Empty;
        }

        return Marshal.PtrToStringUni(blob.Data, (int)(blob.Size / 2))?.TrimEnd('\0') ?? string.Empty;
    }

    private static string FormatAddress(WfpNetEventNative.AddrUnion address, int ipVersion)
    {
        // 按原始字节读：WFP 存的是网络序（用 uint 转 IPAddress 会把字节序弄反）。
        Span<byte> bytes = stackalloc byte[16];
        MemoryMarshal.Write(bytes, in address);

        try
        {
            return ipVersion == 0
                ? new IPAddress(bytes[..4]).ToString()
                : new IPAddress(bytes).ToString();
        }
        catch (Exception)
        {
            return string.Empty;
        }
    }
}
