using WinAppGuard.Contracts;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>把 <see cref="OwnerKey"/> 适配成 Contracts 的签名接口。</summary>
internal sealed class OwnerKeySigner : IServiceSigner, IDisposable
{
    private readonly OwnerKey _key;
    private readonly object _gate = new();

    internal OwnerKeySigner(OwnerKey key)
    {
        _key = key;
    }

    public string Fingerprint => _key.Fingerprint;

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        // ECDsa 实例不保证并发安全；界面可能从多个线程同时发请求。
        lock (_gate)
        {
            return _key.Sign(data);
        }
    }

    public void Dispose() => _key.Dispose();
}
