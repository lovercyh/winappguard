namespace WinAppGuard.Contracts;

/// <summary>
/// 3.1 客户端签名能力。实现由 Core 提供（OwnerKey），
/// Contracts 只依赖这个接口，不反向依赖 Core。
/// </summary>
public interface IServiceSigner
{
    /// <summary>公钥 SHA-256 十六进制（展示/诊断用）。</summary>
    string Fingerprint { get; }

    /// <summary>ECDSA P-256 / SHA-256 签名（DER）。</summary>
    byte[] Sign(ReadOnlySpan<byte> data);
}
