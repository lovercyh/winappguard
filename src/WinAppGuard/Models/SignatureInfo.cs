namespace WinAppGuard.Models;

/// <summary>数字签名检查的结果分类。</summary>
public enum SignatureState
{
    /// <summary>还没检查，或者路径为空。</summary>
    Unknown,

    /// <summary>文件既没有内嵌签名，也没有被任何系统目录收录。</summary>
    Unsigned,

    /// <summary>签名有效且证书链受信任。</summary>
    Valid,

    /// <summary>有签名，但证书链不受信任（例如自签名、根证书不在受信任列表）。</summary>
    Untrusted,

    /// <summary>有签名，但文件内容与签名不匹配（文件在签名之后被改过）。</summary>
    Tampered,

    /// <summary>证书本身有问题：过期、被吊销等。</summary>
    CertificateProblem,

    /// <summary>检查过程出错（文件读不到、API 失败等）。</summary>
    Error,
}

/// <summary>
/// 一个文件的数字签名信息。
///
/// 放在 Models 里而不是 Core 里，是因为它是纯数据：
/// 界面只读它，产生它的逻辑在 Core/DigitalSignature.cs。
/// </summary>
/// <param name="State">结果分类。</param>
/// <param name="SignerName">签名者名称（只有拿到证书时才有值）。</param>
/// <param name="Detail">给用户看的完整说明，含签名来源和 HRESULT 十六进制值。</param>
public sealed record SignatureInfo(SignatureState State, string SignerName, string Detail)
{
    /// <summary>「还没检查」的占位值。</summary>
    public static readonly SignatureInfo None = new(SignatureState.Unknown, string.Empty, string.Empty);
}
