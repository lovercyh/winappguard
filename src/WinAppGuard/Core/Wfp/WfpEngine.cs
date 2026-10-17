using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>WFP 调用失败的异常。带上原始错误码，方便日志里直接对照文档。</summary>
internal sealed class WfpException : Exception
{
    internal WfpException(string operation, uint code)
        : base($"{operation}失败：{WfpNativeMethods.DescribeError(code)}")
    {
        Code = code;
    }

    /// <summary>BFE 返回的原始错误码。</summary>
    internal uint Code { get; }
}

/// <summary>
/// WFP 引擎句柄的封装。
///
/// 职责边界刻意划得很清楚：这里只管**与 BFE 打交道**（开会话、建子层、增删枚举过滤器），
/// 不掺任何"规则"概念。规则怎么映射成过滤器由上层决定，这样规则逻辑可以脱离系统单独测试。
///
/// 会话有两种，实测行为不同：
///   - 普通会话：会话关闭后，其中新建的**非持久化**过滤器消失；持久化过滤器跨重启仍在。
///   - 动态会话（<see cref="Open"/> 的 <c>dynamicSession</c>）：进程一结束（含被强杀），
///     其中所有对象自动消失。严格模式就是靠这个做到「退出即撤销」的。
/// </summary>
internal sealed class WfpEngine : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    private WfpEngine(IntPtr handle, bool isDynamic)
    {
        _handle = handle;
        IsDynamic = isDynamic;
    }

    /// <summary>本会话是否是动态会话。</summary>
    internal bool IsDynamic { get; }

    /// <summary>本程序的子层 GUID。发布后不可更改。</summary>
    internal static Guid SubLayerKey => WfpNativeMethods.OurSubLayerKey;

    /// <summary>打开引擎。失败抛 <see cref="WfpException"/>。</summary>
    /// <param name="dynamicSession">true = 动态会话（进程退出即自动清理）。</param>
    internal static WfpEngine Open(bool dynamicSession = false)
    {
        // 先做一次布局自检：结构体写错的话，后面每个调用都会以莫名其妙的方式失败。
        WfpNativeMethods.EnsureLayout();

        var session = new WfpNativeMethods.FwpmSession
        {
            Flags = dynamicSession ? WfpNativeMethods.FWPM_SESSION_FLAG_DYNAMIC : 0,
        };

        var rc = WfpNativeMethods.FwpmEngineOpen0(
            null,
            WfpNativeMethods.RPC_C_AUTHN_WINNT,
            IntPtr.Zero,
            ref session,
            out var handle);

        if (rc != WfpNativeMethods.ERROR_SUCCESS)
        {
            throw new WfpException("打开 WFP 引擎", rc);
        }

        return new WfpEngine(handle, dynamicSession);
    }

    /// <summary>
    /// 确保我们的子层存在。
    ///
    /// 已经存在（<c>FWP_E_ALREADY_EXISTS</c>）时视为成功 —— 这是重复启动的正常情况，
    /// 不是错误。注意：这里**不会**去改已存在子层的权重，避免把上一次设置的行为悄悄改掉。
    /// </summary>
    /// <param name="persistent">是否持久化。动态会话里必须是 false（动态会话不允许建持久对象）。</param>
    internal void EnsureSublayer(bool persistent)
    {
        ThrowIfDisposed();

        var namePtr = Marshal.StringToHGlobalUni(AppConstants.AppName);

        try
        {
            var subLayer = new WfpNativeMethods.FwpmSubLayer
            {
                SubLayerKey = WfpNativeMethods.OurSubLayerKey,
                DisplayData = new WfpNativeMethods.FwpmDisplayData { Name = namePtr },
                Flags = persistent ? WfpNativeMethods.FWPM_SUBLAYER_FLAG_PERSISTENT : 0,
                Weight = WfpNativeMethods.OurSubLayerWeight,
            };

            var rc = WfpNativeMethods.FwpmSubLayerAdd0(_handle, ref subLayer, IntPtr.Zero);
            if (rc != WfpNativeMethods.ERROR_SUCCESS && rc != WfpNativeMethods.FWP_E_ALREADY_EXISTS)
            {
                throw new WfpException("创建子层", rc);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
        }
    }

    /// <summary>读取子层的真实状态（权重、是否持久化）。子层不存在时抛 <see cref="WfpException"/>。</summary>
    internal (ushort Weight, bool Persistent) ReadSublayer()
    {
        ThrowIfDisposed();

        var key = WfpNativeMethods.OurSubLayerKey;
        var rc = WfpNativeMethods.FwpmSubLayerGetByKey0(_handle, ref key, out var pointer);
        if (rc != WfpNativeMethods.ERROR_SUCCESS)
        {
            throw new WfpException("读取子层", rc);
        }

        try
        {
            var subLayer = Marshal.PtrToStructure<WfpNativeMethods.FwpmSubLayer>(pointer);
            var persistent = (subLayer.Flags & WfpNativeMethods.FWPM_SUBLAYER_FLAG_PERSISTENT) != 0;
            return (subLayer.Weight, persistent);
        }
        finally
        {
            WfpNativeMethods.FwpmFreeMemory0(ref pointer);
        }
    }

    /// <summary>删除子层。不存在时视为成功。</summary>
    internal void DeleteSublayer()
    {
        ThrowIfDisposed();

        var key = WfpNativeMethods.OurSubLayerKey;
        var rc = WfpNativeMethods.FwpmSubLayerDeleteByKey0(_handle, ref key);

        if (rc != WfpNativeMethods.ERROR_SUCCESS && rc != WfpNativeMethods.FWP_E_SUBLAYER_NOT_FOUND)
        {
            if (rc == WfpNativeMethods.FWP_E_IN_USE)
            {
                throw new WfpException(
                    "删除子层（还有过滤器引用它，必须先删光该子层下的过滤器）", rc);
            }

            throw new WfpException("删除子层", rc);
        }
    }

    /// <summary>列出本子层下所有过滤器的 key（不排序，顺序由 WFP 决定）。</summary>
    internal IReadOnlyList<Guid> ListOurFilterKeys()
    {
        ThrowIfDisposed();

        var keys = new List<Guid>();

        var rc = WfpNativeMethods.FwpmFilterCreateEnumHandle0(_handle, IntPtr.Zero, out var enumHandle);
        if (rc != WfpNativeMethods.ERROR_SUCCESS)
        {
            throw new WfpException("创建过滤器枚举器", rc);
        }

        try
        {
            while (true)
            {
                rc = WfpNativeMethods.FwpmFilterEnum0(_handle, enumHandle, 64, out var entries, out var returned);
                if (rc != WfpNativeMethods.ERROR_SUCCESS)
                {
                    throw new WfpException("枚举过滤器", rc);
                }

                if (entries == IntPtr.Zero || returned == 0)
                {
                    break;
                }

                try
                {
                    for (var i = 0; i < returned; i++)
                    {
                        var itemPtr = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        if (itemPtr == IntPtr.Zero)
                        {
                            continue;
                        }

                        var filter = Marshal.PtrToStructure<WfpNativeMethods.FwpmFilter>(itemPtr);
                        if (filter.SubLayerKey == WfpNativeMethods.OurSubLayerKey)
                        {
                            keys.Add(filter.FilterKey);
                        }
                    }
                }
                finally
                {
                    WfpNativeMethods.FwpmFreeMemory0(ref entries);
                }
            }
        }
        finally
        {
            WfpNativeMethods.FwpmFilterDestroyEnumHandle0(_handle, enumHandle);
        }

        return keys;
    }

    /// <summary>按 key 删除一条过滤器。不存在时抛 <see cref="WfpException"/>。</summary>
    internal void DeleteFilter(Guid filterKey)
    {
        ThrowIfDisposed();

        var key = filterKey;
        var rc = WfpNativeMethods.FwpmFilterDeleteByKey0(_handle, ref key);
        if (rc != WfpNativeMethods.ERROR_SUCCESS)
        {
            throw new WfpException($"删除过滤器 {filterKey}", rc);
        }
    }

    /// <summary>
    /// 删光本子层下的所有过滤器，返回实际删除的条数。
    ///
    /// 这是 <c>--recover</c> 和各处"整体撤销"的核心步骤。
    /// 顺序很重要：**必须先删过滤器再删子层**，否则子层会因为"被引用"而删不掉
    /// （<c>FWP_E_IN_USE 0x8032000A</c>，实测踩过）。
    /// </summary>
    internal int DeleteAllOurFilters()
    {
        ThrowIfDisposed();

        var deleted = 0;

        foreach (var key in ListOurFilterKeys())
        {
            var local = key;
            var rc = WfpNativeMethods.FwpmFilterDeleteByKey0(_handle, ref local);

            // 枚举与删除之间的竞态（别的实例刚好删掉了）不算错误。
            if (rc == WfpNativeMethods.ERROR_SUCCESS)
            {
                deleted++;
            }
            else if (rc != WfpNativeMethods.FWP_E_FILTER_NOT_FOUND)
            {
                throw new WfpException($"删除过滤器 {key}", rc);
            }
        }

        return deleted;
    }

    /// <summary>
    /// 添加一条"按程序身份匹配"的过滤器。
    /// </summary>
    /// <param name="filterKey">调用方生成的确定性 key（重复执行时不会产生重复规则）。</param>
    /// <param name="displayName">显示名称。BFE 要求必填，不能传 null。</param>
    /// <param name="exePath">目标程序的可执行文件完整路径。</param>
    /// <param name="action">动作，用 <see cref="WfpNativeMethods.FWP_ACTION_BLOCK"/> 或 <see cref="WfpNativeMethods.FWP_ACTION_PERMIT"/>。</param>
    /// <param name="weight">同一子层内的权重，数值大的优先。</param>
    /// <param name="persistent">是否持久化（跨重启保留）。动态会话里必须为 false。</param>
    internal ulong AddAppIdFilter(
        Guid filterKey,
        string displayName,
        string exePath,
        uint action,
        ulong weight,
        bool persistent)
    {
        ThrowIfDisposed();

        var appIdPtr = IntPtr.Zero;
        var weightPtr = IntPtr.Zero;
        var namePtr = IntPtr.Zero;
        var conditionPtr = IntPtr.Zero;

        try
        {
            var rc = WfpNativeMethods.FwpmGetAppIdFromFileName0(exePath, out appIdPtr);
            if (rc != WfpNativeMethods.ERROR_SUCCESS)
            {
                throw new WfpException($"取程序身份（{exePath}）", rc);
            }

            weightPtr = Marshal.AllocHGlobal(sizeof(ulong));
            Marshal.WriteInt64(weightPtr, unchecked((long)weight));

            namePtr = Marshal.StringToHGlobalUni(displayName);

            conditionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNativeMethods.FwpmFilterCondition>());
            var condition = new WfpNativeMethods.FwpmFilterCondition
            {
                FieldKey = WfpNativeMethods.ConditionAleAppId,
                MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                ConditionValue = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_BYTE_BLOB_TYPE,
                    Value = appIdPtr,
                },
            };
            Marshal.StructureToPtr(condition, conditionPtr, false);

            var filter = new WfpNativeMethods.FwpmFilter
            {
                FilterKey = filterKey,
                DisplayData = new WfpNativeMethods.FwpmDisplayData { Name = namePtr },
                Flags = persistent ? WfpNativeMethods.FWPM_FILTER_FLAG_PERSISTENT : 0,
                LayerKey = WfpNativeMethods.LayerAleAuthConnectV4,
                SubLayerKey = WfpNativeMethods.OurSubLayerKey,
                Weight = new WfpNativeMethods.FwpValue
                {
                    Type = WfpNativeMethods.FWP_UINT64,
                    Value = weightPtr,
                },
                NumFilterConditions = 1,
                FilterCondition = conditionPtr,
                Action = new WfpNativeMethods.FwpmAction { Type = action },
            };

            rc = WfpNativeMethods.FwpmFilterAdd0(_handle, ref filter, IntPtr.Zero, out var id);
            if (rc != WfpNativeMethods.ERROR_SUCCESS)
            {
                throw new WfpException($"添加过滤器（{displayName}）", rc);
            }

            return id;
        }
        finally
        {
            if (appIdPtr != IntPtr.Zero)
            {
                WfpNativeMethods.FwpmFreeMemory0(ref appIdPtr);
            }

            if (conditionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(conditionPtr);
            }

            if (namePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(namePtr);
            }

            if (weightPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(weightPtr);
            }
        }
    }

    /// <summary>
    /// 由一段文本生成**确定性**的过滤器 key。
    ///
    /// 同一个程序 + 同一种规则永远算出同一个 key，所以"重复添加"不会产生重复规则，
    /// 而且重启后还能按 key 找回自己建的过滤器。用 SHA-256 的前 16 字节。
    /// </summary>
    internal static Guid BuildFilterKey(string seed)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed.ToLowerInvariant()));
        return new Guid(hash.AsSpan(0, 16));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_handle != IntPtr.Zero)
        {
            WfpNativeMethods.FwpmEngineClose0(_handle);
            _handle = IntPtr.Zero;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
