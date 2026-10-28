using System.Runtime.InteropServices;
using WinAppGuard.Core.Diagnostics.AntiScan;

namespace WinAppGuard.Core.Diagnostics.Traffic;

/// <summary>
/// 4.1：只读探测「Npcap 是否真的能用」——加载 wpcap、枚举网卡、打开再关掉一个设备。
///
/// 安装器用它做最后一步检查：驱动文件在、但驱动服务没起来时，
/// 只检查文件会得到假阳性。这里不启动任何采集线程，也不抓包。
/// </summary>
public static class NpcapProbe
{
    public static bool TryOpen(out string? error)
    {
        error = null;

        var path = NpcapLocator.FindWpcapPath();

        if (path is null)
        {
            error = "未找到 wpcap.dll。";
            return false;
        }

        IntPtr library = IntPtr.Zero;
        var devices = IntPtr.Zero;
        var handle = IntPtr.Zero;

        try
        {
            library = NativeLibrary.Load(path);
            var findAll = Marshal.GetDelegateForFunctionPointer<FindAllDevsDelegate>(
                NativeLibrary.GetExport(library, "pcap_findalldevs"));
            var freeAll = Marshal.GetDelegateForFunctionPointer<FreeAllDevsDelegate>(
                NativeLibrary.GetExport(library, "pcap_freealldevs"));
            var openLive = Marshal.GetDelegateForFunctionPointer<OpenLiveDelegate>(
                NativeLibrary.GetExport(library, "pcap_open_live"));
            var close = Marshal.GetDelegateForFunctionPointer<CloseDelegate>(
                NativeLibrary.GetExport(library, "pcap_close"));
            var getError = Marshal.GetDelegateForFunctionPointer<GetErrorDelegate>(
                NativeLibrary.GetExport(library, "pcap_geterr"));

            var errbuf = new byte[512];

            if (findAll(out devices, errbuf) != 0 || devices == IntPtr.Zero)
            {
                error = ReadErr(errbuf);
                return false;
            }

            var current = devices;

            while (current != IntPtr.Zero)
            {
                var item = Marshal.PtrToStructure<PcapIf>(current);
                current = item.Next;

                if ((item.Flags & PcapIfLoopback) != 0)
                {
                    continue;
                }

                var name = Marshal.PtrToStringAnsi(item.Name);

                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var device = openLive(name, 64, 0, 100, errbuf);

                if (device == IntPtr.Zero)
                {
                    error = $"打开网卡失败（{name}）：{ReadErr(errbuf)}";
                    continue;
                }

                handle = device;
                return true;
            }

            error ??= "没有可用的活动网卡。";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            try
            {
                if (handle != IntPtr.Zero)
                {
                    var close = Marshal.GetDelegateForFunctionPointer<CloseDelegate>(
                        NativeLibrary.GetExport(library, "pcap_close"));
                    close(handle);
                }
            }
            catch (Exception)
            {
                // 关闭失败不影响探测结论。
            }

            try
            {
                if (devices != IntPtr.Zero)
                {
                    var freeAll = Marshal.GetDelegateForFunctionPointer<FreeAllDevsDelegate>(
                        NativeLibrary.GetExport(library, "pcap_freealldevs"));
                    freeAll(devices);
                }
            }
            catch (Exception)
            {
                // 释放失败不影响探测结论。
            }

            if (library != IntPtr.Zero)
            {
                try
                {
                    NativeLibrary.Free(library);
                }
                catch (Exception)
                {
                    // 释放失败不影响探测结论。
                }
            }
        }
    }

    private const uint PcapIfLoopback = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapIf
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int FindAllDevsDelegate(out IntPtr devices, byte[] errbuf);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void FreeAllDevsDelegate(IntPtr devices);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr OpenLiveDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string device,
        int snapLength,
        int promiscuous,
        int timeoutMs,
        byte[] errbuf);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void CloseDelegate(IntPtr handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr GetErrorDelegate(IntPtr handle);

    private static string ReadErr(byte[] buf)
    {
        var end = Array.IndexOf(buf, (byte)0);
        var length = end < 0 ? buf.Length : end;
        return System.Text.Encoding.ASCII.GetString(buf, 0, length);
    }
}
