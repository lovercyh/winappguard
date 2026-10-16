using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using WinAppGuard.Interop;

namespace WinAppGuard.Core;

/// <summary>
/// 一次签名验证的原始结果。
/// </summary>
/// <param name="HResult">WinVerifyTrust 的返回值，0 表示有效且受信任。</param>
/// <param name="SignerName">签名者名称；取不到时是空字符串。</param>
/// <param name="FromCatalog">true 表示结论来自目录签名（.cat）而不是文件内嵌签名。</param>
internal readonly record struct TrustResult(int HResult, string SignerName, bool FromCatalog)
{
    /// <summary>签名有效且受信任。</summary>
    public bool IsTrusted => HResult == ErrorSuccess;

    /// <summary>
    /// 是否是「这个文件压根没有签名」这一类的返回码。
    ///
    /// 这个判断很关键：只有属于这一类，才应该再去查目录签名；
    /// 如果是「有签名但验证失败」（被篡改、证书不受信任），那本身就是结论，
    /// 不能再去查目录把问题洗白。
    /// </summary>
    public bool IsNoSignature =>
        HResult is TrustENosignature or TrustENoSignedData or TrustESubjectFormUnknown;

    // ---------------- WinVerifyTrust 的常见返回码 ----------------

    public const int ErrorSuccess = 0;
    public const int TrustENosignature = unchecked((int)0x800B0100);
    public const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    public const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
    public const int TrustENoSignedData = unchecked((int)0x800B0107);
    public const int TrustEBadDigest = unchecked((int)0x80096010);
    public const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    public const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    public const int CertEChaining = unchecked((int)0x800B010A);
    public const int CertEExpired = unchecked((int)0x800B0101);
    public const int CertERevoked = unchecked((int)0x800B010C);
    public const int CertECnNoMatch = unchecked((int)0x800B010F);
    public const int CryptESecuritySettings = unchecked((int)0x80092026);

    /// <summary>构造一个「没有签名」的结果。</summary>
    public static TrustResult NoSignature => new(TrustENosignature, string.Empty, false);
}

/// <summary>
/// 数字签名的底层验证。
///
/// 这个类负责跟 Win32 打交道，把「一个文件到底有没有被可信地签名」问清楚。
/// 它要处理两套完全不同的机制：
///
///   **内嵌签名** —— 签名存在 exe 自己的 PE 证书表里。
///                    第三方软件（Chrome / Steam / Git / 微信）基本都用这种。
///                    验证方式：WinVerifyTrust + WTD_CHOICE_FILE。
///
///   **目录签名** —— 签名存在 C:\Windows\System32\CatRoot\ 的 .cat 文件里，
///                    exe 本身什么都没有。大量 Windows 系统文件只有这种
///                    （notepad.exe / cmd.exe / winver.exe 都是）。
///                    验证方式：算文件哈希 → 用哈希找到所属 .cat → 验证 .cat。
///
/// **只查内嵌签名会把 notepad.exe 这类系统文件误报成「未签名」**，
/// 所以两条路径都必须走。
/// </summary>
internal static class CertificateTrust
{
    /// <summary>WINTRUST_ACTION_GENERIC_VERIFY_V2。</summary>
    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    // ---------------- WINTRUST_DATA 用的常量 ----------------

    /// <summary>WTD_UI_NONE：不弹任何界面。</summary>
    private const int WtdUiNone = 2;

    /// <summary>WTD_CHOICE_FILE：验证一个文件的内嵌签名。</summary>
    private const int WtdChoiceFile = 1;

    /// <summary>WTD_CHOICE_CATALOG：验证目录签名。</summary>
    private const int WtdChoiceCatalog = 2;

    /// <summary>WTD_STATEACTION_VERIFY。</summary>
    private const int WtdStateActionVerify = 1;

    /// <summary>WTD_STATEACTION_CLOSE（必须调用，否则泄漏内部状态）。</summary>
    private const int WtdStateActionClose = 2;

    /// <summary>WTD_REVOCATION_CHECK_CHAIN：检查整条证书链的吊销状态。</summary>
    private const int WtdRevocationCheckChain = 0x00040000;

    /// <summary>WTD_CACHE_ONLY_URL_RETRIEVAL：只读本地缓存的吊销信息，绝不联网。</summary>
    private const int WtdCacheOnlyUrlRetrieval = 0x00001000;

    /// <summary>
    /// 目录签名用的哈希算法。
    ///
    /// 用 SHA-256 而不是已废弃的 SHA-1：Windows 8 以后系统自带的目录都用 SHA-256，
    /// 而本项目只支持 Windows 10/11，所以不需要兼容 SHA-1 的老目录。
    /// </summary>
    private const string CatalogHashAlgorithm = "SHA256";

    // ==================================================================
    // 对外接口
    // ==================================================================

    /// <summary>
    /// 验证文件的**内嵌签名**。
    /// </summary>
    /// <param name="filePath">文件完整路径。</param>
    /// <param name="allowNetwork">是否允许联网查询证书吊销列表。</param>
    public static TrustResult VerifyEmbedded(string filePath, bool allowNetwork)
    {
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());

        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var data = new WinTrustData
            {
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = 0,
                dwUnionChoice = WtdChoiceFile,
                pFile = fileInfoPtr,
                dwUIContext = 0,
            };
            data.cbStruct = Marshal.SizeOf<WinTrustData>();

            return RunVerifyTrust(ref data, allowNetwork, fromCatalog: false);
        }
        finally
        {
            // 结构体里的字符串是编组器分配的，必须显式释放，否则每次调用都泄漏一小块。
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    /// <summary>
    /// 验证文件的**目录签名**。
    ///
    /// 流程：算文件哈希 → 用哈希找到所属的 .cat → 验证 .cat 里的这条记录。
    /// 返回「没有签名」表示**没有任何目录收录这个文件**。
    /// </summary>
    /// <param name="filePath">文件完整路径。</param>
    /// <param name="allowNetwork">是否允许联网查询证书吊销列表。</param>
    public static TrustResult VerifyCatalog(string filePath, bool allowNetwork)
    {
        var hCatAdmin = IntPtr.Zero;
        var hCatInfo = IntPtr.Zero;
        var hashBuffer = IntPtr.Zero;
        var catalogInfoPtr = IntPtr.Zero;
        FileStream? fileStream = null;

        try
        {
            // 1) 打开目录签名管理上下文
            if (!NativeMethods.CryptCATAdminAcquireContext2(
                    out hCatAdmin, IntPtr.Zero, CatalogHashAlgorithm, IntPtr.Zero, 0))
            {
                return new TrustResult(LastErrorAsHResult(), string.Empty, true);
            }

            // 2) 打开文件（取句柄给下一步算哈希用）
            try
            {
                fileStream = File.OpenRead(filePath);
            }
            catch (Exception)
            {
                return TrustResult.NoSignature with { FromCatalog = true };
            }

            var fileHandle = fileStream.SafeFileHandle.DangerousGetHandle();

            // 3) 算文件哈希。第一次问长度，第二次取内容。
            var hashLength = 0;
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(
                    hCatAdmin, fileHandle, ref hashLength, null, 0) || hashLength <= 0)
            {
                return new TrustResult(LastErrorAsHResult(), string.Empty, true);
            }

            var hash = new byte[hashLength];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(
                    hCatAdmin, fileHandle, ref hashLength, hash, 0))
            {
                return new TrustResult(LastErrorAsHResult(), string.Empty, true);
            }

            // 4) 按哈希找目录。返回 Zero 就是「没有任何目录收录这个文件」。
            var previousCatalog = IntPtr.Zero;
            hCatInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash, hashLength, 0, ref previousCatalog);

            if (hCatInfo == IntPtr.Zero)
            {
                // 这是「没有目录签名」的确切信号，不是错误。
                return TrustResult.NoSignature with { FromCatalog = true };
            }

            // 5) 取目录文件路径
            var catalogInfo = new CatalogInfo { cbStruct = Marshal.SizeOf<CatalogInfo>() };
            if (!NativeMethods.CryptCATCatalogInfoFromContext(hCatInfo, ref catalogInfo, 0))
            {
                return new TrustResult(LastErrorAsHResult(), string.Empty, true);
            }

            // 6) 组装 WINTRUST_CATALOG_INFO 并验证
            // 成员标签 = 文件哈希的十六进制大写字符串（目录签名就是靠它定位记录的）
            var memberTag = Convert.ToHexString(hash);

            hashBuffer = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, hashBuffer, hash.Length);

            var catalogInfo2 = new WinTrustCatalogInfo
            {
                cbStruct = Marshal.SizeOf<WinTrustCatalogInfo>(),
                dwCatalogVersion = 0,
                CatalogFilePath = catalogInfo.CatalogFile,
                MemberTag = memberTag,
                MemberFilePath = filePath,
                hMemberFile = fileHandle,
                CalculatedFileHash = hashBuffer,
                cbCalculatedFileHash = hash.Length,
                CatalogContext = IntPtr.Zero,
                hCatAdmin = hCatAdmin,
            };

            catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(catalogInfo2, catalogInfoPtr, fDeleteOld: false);

            var data = new WinTrustData
            {
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = 0,
                dwUnionChoice = WtdChoiceCatalog,
                pFile = catalogInfoPtr,   // 联合体：目录模式这里是 WinTrustCatalogInfo 的指针
                dwUIContext = 0,
            };
            data.cbStruct = Marshal.SizeOf<WinTrustData>();

            return RunVerifyTrust(ref data, allowNetwork, fromCatalog: true);
        }
        catch (Exception)
        {
            return new TrustResult(unchecked((int)0x80004005), string.Empty, true);
        }
        finally
        {
            // 所有非托管资源都要释放，漏一个就泄漏一块内存。
            if (catalogInfoPtr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WinTrustCatalogInfo>(catalogInfoPtr);
                Marshal.FreeHGlobal(catalogInfoPtr);
            }

            if (hashBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(hashBuffer);
            }

            fileStream?.Dispose();

            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }

            if (hCatAdmin != IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }
    }

    // ==================================================================
    // 内部实现
    // ==================================================================

    /// <summary>
    /// 真正调用 WinVerifyTrust 并取回签名者，收尾时释放状态。
    /// 内嵌签名和目录签名共用这段。
    /// </summary>
    private static TrustResult RunVerifyTrust(ref WinTrustData data, bool allowNetwork, bool fromCatalog)
    {
        data.dwStateAction = WtdStateActionVerify;
        data.hWVTStateData = IntPtr.Zero;
        data.pwszURLReference = IntPtr.Zero;

        // 都要求检查整条证书链的吊销状态；
        // 只有在「不允许联网」时才加上"只读本地缓存"。
        data.dwProvFlags = WtdRevocationCheckChain |
                           (allowNetwork ? 0 : WtdCacheOnlyUrlRetrieval);

        var actionId = WinTrustActionGenericVerifyV2;
        var result = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);

        // 签名者名字必须在 CLOSE 之前取 —— CLOSE 之后状态就被释放了。
        var signerName = result == TrustResult.ErrorSuccess
            ? TryReadSignerName(data.hWVTStateData)
            : string.Empty;

        // 无论成功失败都要 CLOSE，否则 WinVerifyTrust 的内部状态会一直累积。
        data.dwStateAction = WtdStateActionClose;
        NativeMethods.WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);

        return new TrustResult(result, signerName, fromCatalog);
    }

    /// <summary>
    /// 从验证状态句柄里把签名者证书挖出来，取一个给人看的名字。
    ///
    /// 为什么用这条路而不是 X509Certificate.CreateFromSignedFile：
    ///   1. 后者在 .NET 9 起被标记为过时，而且没有等价替代品；
    ///   2. 后者只认**内嵌签名**，目录签名的文件取不到名字 —— 而这里两条路径都能用。
    /// </summary>
    private static string TryReadSignerName(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            var providerData = NativeMethods.WTHelperProvDataFromStateData(stateData);
            if (providerData == IntPtr.Zero)
            {
                return string.Empty;
            }

            // 第一个签名者（索引 0）就是签署这个文件的主体。
            var signer = NativeMethods.WTHelperGetProvSignerFromChain(
                providerData, dwIdx: 0, fCounterSigner: false, dwIdx2: 0);
            if (signer == IntPtr.Zero)
            {
                return string.Empty;
            }

            var providerCert = NativeMethods.WTHelperGetProvCertFromChain(signer, 0);
            if (providerCert == IntPtr.Zero)
            {
                return string.Empty;
            }

            var certPtr = Marshal.PtrToStructure<CryptProviderCert>(providerCert).pCert;
            if (certPtr == IntPtr.Zero)
            {
                return string.Empty;
            }

            // 取出证书的编码字节，交给 X509CertificateLoader 解析。
            // 走这条路就不需要任何已过时的 API。
            var context = Marshal.PtrToStructure<CertContext>(certPtr);
            if (context.pbCertEncoded == IntPtr.Zero || context.cbCertEncoded <= 0)
            {
                return string.Empty;
            }

            var encoded = new byte[context.cbCertEncoded];
            Marshal.Copy(context.pbCertEncoded, encoded, 0, encoded.Length);

            using var certificate = X509CertificateLoader.LoadCertificate(encoded);

            // SimpleName 会按 CN → O → OU 挑一个最适合给人看的名字，
            // 典型结果是「Microsoft Windows」「Google LLC」这种。
            var simpleName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(simpleName) ? certificate.Subject : simpleName;
        }
        catch (Exception)
        {
            // 名字只是附加信息，取不到不影响判定结果。
            return string.Empty;
        }
    }

    /// <summary>把 GetLastError() 的错误码转成 HRESULT 形式，方便和 WinVerifyTrust 的返回码统一处理。</summary>
    private static int LastErrorAsHResult()
    {
        var error = Marshal.GetLastWin32Error();
        if (error == 0)
        {
            return unchecked((int)0x80004005); // 没拿到具体错误就用 E_FAIL 兜底
        }

        return unchecked((int)(0x80070000 | (uint)(error & 0xFFFF)));
    }
}
