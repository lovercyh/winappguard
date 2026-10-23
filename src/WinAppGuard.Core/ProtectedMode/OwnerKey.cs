using System.Security.Cryptography;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>
/// 受保护模式的所有者密钥（3.1）：ECDSA P-256。
///
/// 私钥只以两种形式存在：
///   - 当前进程内存里（本对象），用后 Dispose；
///   - DPAPI 用户级加密后的 blob（client-key.dpapi）。
/// 服务端不需要本类来验签（用 <see cref="Verify"/> + 公钥即可）。
/// </summary>
internal sealed class OwnerKey : IDisposable
{
    private readonly ECDsa _key;

    private OwnerKey(ECDsa key)
    {
        _key = key;
        PublicKey = key.ExportSubjectPublicKeyInfo();
        Fingerprint = ComputeFingerprint(PublicKey);
    }

    /// <summary>SPKI 公钥（可以公开；服务端存的就是它）。</summary>
    internal byte[] PublicKey { get; }

    /// <summary>公钥的 SHA-256 十六进制（64 字符）。不是秘密。</summary>
    internal string Fingerprint { get; }

    /// <summary>生成一把新的 P-256 私钥。</summary>
    internal static OwnerKey Create()
        => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    /// <summary>只导入公钥（用于验证；此对象不能签名）。</summary>
    internal static OwnerKey ImportPublicKey(ReadOnlySpan<byte> publicKey)
    {
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(publicKey, out _);
        return new OwnerKey(key);
    }

    /// <summary>把私钥导出为 PKCS#8 → DPAPI 用户级加密。明文会被清零。</summary>
    internal byte[] ProtectPrivateKey(ReadOnlySpan<byte> entropy)
    {
        var pkcs8 = _key.ExportPkcs8PrivateKey();

        try
        {
            return Dpapi.Protect(pkcs8, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    /// <summary>DPAPI 解密 blob → 导入私钥。明文会被清零。</summary>
    internal static OwnerKey Unprotect(
        ReadOnlySpan<byte> protectedBlob, ReadOnlySpan<byte> entropy)
    {
        var plain = Dpapi.Unprotect(protectedBlob, entropy);

        try
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(plain, out _);
            return new OwnerKey(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>对数据签名（ECDSA P-256 / SHA-256，DER 编码）。</summary>
    internal byte[] Sign(ReadOnlySpan<byte> data)
        => _key.SignData(data, HashAlgorithmName.SHA256);

    /// <summary>用 SPKI 公钥验签；任何异常都按“验签失败”处理。</summary>
    internal static bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        catch (Exception)
        {
            return false;
        }
    }

    internal static string ComputeFingerprint(ReadOnlySpan<byte> publicKey)
        => Convert.ToHexString(SHA256.HashData(publicKey));

    public void Dispose() => _key.Dispose();
}
