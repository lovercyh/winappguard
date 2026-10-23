using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>
/// DPAPI 的最小封装（3.1 受保护模式）。
///
/// 只用**用户级** DPAPI（不带 CRYPTPROTECT_LOCAL_MACHINE）：
/// 密文只能由同一个 Windows 用户解密，换账户/换机器都解不开。
/// entropy 用来把密文绑定到本次安装；它不是机密，存在 protected-mode.json 里。
/// </summary>
internal static class Dpapi
{
    private const uint CryptProtectUiForbidden = 0x1;

    internal static byte[] Protect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy)
    {
        if (data.Length == 0)
        {
            throw new ArgumentException("不能加密空数据。", nameof(data));
        }

        var input = ToBlob(data);
        var entropyBlob = ToBlob(entropy);
        var output = default(DataBlob);

        try
        {
            if (!CryptProtectData(
                    ref input,
                    null,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(), "DPAPI 加密失败");
            }

            return FromBlob(output);
        }
        finally
        {
            FreeBlob(ref input);
            FreeBlob(ref entropyBlob);

            if (output.pbData != IntPtr.Zero)
            {
                LocalFree(output.pbData);
            }
        }
    }

    internal static byte[] Unprotect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy)
    {
        if (data.Length == 0)
        {
            throw new ArgumentException("不能解密空数据。", nameof(data));
        }

        var input = ToBlob(data);
        var entropyBlob = ToBlob(entropy);
        var output = default(DataBlob);

        try
        {
            if (!CryptUnprotectData(
                    ref input,
                    IntPtr.Zero,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(), "DPAPI 解密失败");
            }

            return FromBlob(output);
        }
        finally
        {
            FreeBlob(ref input);
            FreeBlob(ref entropyBlob);

            if (output.pbData != IntPtr.Zero)
            {
                LocalFree(output.pbData);
            }
        }
    }

    private static DataBlob ToBlob(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return default;
        }

        var bytes = data.ToArray();
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        CryptographicOperations.ZeroMemory(bytes);

        return new DataBlob
        {
            cbData = data.Length,
            pbData = pointer,
        };
    }

    private static byte[] FromBlob(DataBlob blob)
    {
        if (blob.cbData <= 0 || blob.pbData == IntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        var result = new byte[blob.cbData];
        Marshal.Copy(blob.pbData, result, 0, blob.cbData);
        return result;
    }

    private static void FreeBlob(ref DataBlob blob)
    {
        if (blob.pbData != IntPtr.Zero)
        {
            // 输入缓冲区里可能有私钥，先清零再释放。
            var zeros = new byte[blob.cbData];
            Marshal.Copy(zeros, 0, blob.pbData, blob.cbData);

            Marshal.FreeHGlobal(blob.pbData);
            blob.pbData = IntPtr.Zero;
            blob.cbData = 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? dataDescription,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        IntPtr dataDescription,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
