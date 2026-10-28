using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Interop;
using WinAppGuard.Models;

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

    /// <summary>
    /// 子层实际的持久化状态（由 <see cref="EnsureSublayer"/> 读回，不是"打算设成什么"）。
    ///
    /// 为什么要以读回来的为准：持久化的过滤器**不能**挂在非持久化的子层上，
    /// WFP 会报 <c>FWP_E_INCOMPATIBLE_TXN (0x80320016)</c>
    /// （"该调用尝试将两个生存时间不兼容的对象相互关联"）。
    /// 如果不按实际情况对齐，写入就会以一个看不懂的错误码失败。
    /// </summary>
    internal bool SublayerPersistent { get; private set; }



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

        // 已存在就直接用系统里的实际状态（也避免每次打开引擎都走创建路径）。
        try
        {
            SublayerPersistent = ReadSublayer().Persistent;
            return;
        }
        catch (WfpException)
        {
            // 不存在：继续创建。
        }

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

            // 创建时直接带上保护性 DACL（比"先创建再改安全信息"安全得多，
            // 后者在 VM 上实测会把服务启动卡死）。
            var descriptor = TryBuildProtectiveSd();

            var rc = WfpNativeMethods.FwpmSubLayerAdd0(_handle, ref subLayer, descriptor);

            if (descriptor != IntPtr.Zero)
            {
                LocalFree(descriptor);
            }

            if (rc != WfpNativeMethods.ERROR_SUCCESS
                && rc != WfpNativeMethods.FWP_E_ALREADY_EXISTS)
            {
                // 极少数环境不接受自定义安全描述符：退回默认 SD，保证功能可用。
                LocalLog.Warning($"[WAG-WFP-001] Failed to harden the sublayer; falling back to the default security descriptor: 0x{rc:X8}");
                rc = WfpNativeMethods.FwpmSubLayerAdd0(_handle, ref subLayer, IntPtr.Zero);
            }

            if (rc == WfpNativeMethods.ERROR_SUCCESS)
            {
                SublayerPersistent = persistent;
                return;
            }

            if (rc == WfpNativeMethods.FWP_E_ALREADY_EXISTS)
            {
                // 已经存在：以**系统里实际的状态**为准，不能沿用调用方的假设。
                // （比如上一次创建的是非持久化子层，这次想建持久化的 —— 加不进去，
                //   但后续过滤器必须按"非持久化"来处理，否则会 0x80320016。）
                SublayerPersistent = ReadSublayer().Persistent;
                return;
            }

            throw new WfpException("创建子层", rc);
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

    /// <summary>枚举结果里的一条过滤器（只取上层用得上的字段）。</summary>
    internal readonly record struct WfpFilterInfo(
        Guid Key,
        string? Name,
        string? Description,
        Guid LayerKey,
        uint ActionType,
        ulong FilterId);

    /// <summary>
    /// 列出本子层下的所有过滤器。
    ///
    /// 会一并读出显示名称和说明 —— 2.0 的规则就存在说明字段里
    /// （格式见 <see cref="WfpRule"/>），所以"列出规则"实际上就是这一句。
    /// </summary>
    internal IReadOnlyList<WfpFilterInfo> ListOurFilters()
    {
        ThrowIfDisposed();

        var filters = new List<WfpFilterInfo>();

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
                        if (filter.SubLayerKey != WfpNativeMethods.OurSubLayerKey)
                        {
                            continue;
                        }

                        // 字符串必须在 FwpmFreeMemory0 之前读出来 —— 之后这块内存就还给系统了。
                        filters.Add(new WfpFilterInfo(
                            filter.FilterKey,
                            Marshal.PtrToStringUni(filter.DisplayData.Name),
                            Marshal.PtrToStringUni(filter.DisplayData.Description),
                            filter.LayerKey,
                            filter.Action.Type,
                            filter.FilterId));
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

        return filters;
    }

    /// <summary>本子层下所有过滤器的 key（<see cref="ListOurFilters"/> 的便捷版本）。</summary>
    internal IReadOnlyList<Guid> ListOurFilterKeys()
        => ListOurFilters().Select(filter => filter.Key).ToList();

    /// <summary>3.4：读取本工具子层的 SDDL（验收用）。</summary>
    internal string? ReadSublayerSecuritySddl()
    {
        ThrowIfDisposed();
        return WfpDaclInspector.ReadSublayer(_handle);
    }

    /// <summary>3.4：读取一条过滤器的 SDDL（验收用）。</summary>
    internal string? ReadFilterSecuritySddl(Guid filterKey)
    {
        ThrowIfDisposed();
        return WfpDaclInspector.ReadFilter(_handle, filterKey);
    }

    /// <summary>
    /// 4.2：临时阻断某个 DHCP 服务器（只拦来自该 IP 的 DHCP 应答）。
    ///
    /// 条件：UDP + 远端地址 + 远端端口 67。挂在入站 accept 层，只影响新连接，不碰已有连接。
    /// </summary>
    internal ulong AddDhcpInboundFilter(
        Guid filterKey,
        string displayName,
        string? description,
        System.Net.IPAddress serverAddress,
        uint action,
        ulong weight,
        bool persistent)
    {
        ThrowIfDisposed();

        var isV4 = serverAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var layerKey = isV4
            ? WfpNativeMethods.LayerAleAuthRecvAcceptV4
            : WfpNativeMethods.LayerAleAuthRecvAcceptV6;

        var bytes = serverAddress.GetAddressBytes();
        var v4Value = isV4
            ? (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3])
            : 0u;

        var namePtr = Marshal.StringToHGlobalUni(displayName);
        var descriptionPtr = description is null ? IntPtr.Zero : Marshal.StringToHGlobalUni(description);
        var weightPtr = Marshal.AllocHGlobal(sizeof(ulong));
        var conditionSize = Marshal.SizeOf<WfpNativeMethods.FwpmFilterCondition>();
        var conditionsPtr = Marshal.AllocHGlobal(conditionSize * 3);
        var addressPtr = IntPtr.Zero;

        try
        {
            Marshal.WriteInt64(weightPtr, unchecked((long)weight));

            var protocolCondition = new WfpNativeMethods.FwpmFilterCondition
            {
                FieldKey = WfpNativeMethods.ConditionIpProtocol,
                MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                ConditionValue = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_UINT8,
                    Value = (IntPtr)17,
                },
            };

            WfpNativeMethods.FwpConditionValue addressValue;

            if (isV4)
            {
                addressValue = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_UINT32,
                    Value = (IntPtr)(long)v4Value,
                };
            }
            else
            {
                addressPtr = Marshal.AllocHGlobal(16);
                Marshal.Copy(bytes, 0, addressPtr, 16);

                addressValue = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_BYTE_ARRAY16_TYPE,
                    Value = addressPtr,
                };
            }

            var addressCondition = new WfpNativeMethods.FwpmFilterCondition
            {
                FieldKey = WfpNativeMethods.ConditionIpRemoteAddress,
                MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                ConditionValue = addressValue,
            };

            var portCondition = new WfpNativeMethods.FwpmFilterCondition
            {
                FieldKey = WfpNativeMethods.ConditionIpRemotePort,
                MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                ConditionValue = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_UINT16,
                    Value = (IntPtr)67,
                },
            };

            Marshal.StructureToPtr(protocolCondition, conditionsPtr, false);
            Marshal.StructureToPtr(addressCondition, IntPtr.Add(conditionsPtr, conditionSize), false);
            Marshal.StructureToPtr(portCondition, IntPtr.Add(conditionsPtr, conditionSize * 2), false);

            var filter = new WfpNativeMethods.FwpmFilter
            {
                FilterKey = filterKey,
                DisplayData = new WfpNativeMethods.FwpmDisplayData
                {
                    Name = namePtr,
                    Description = descriptionPtr,
                },
                Flags = persistent ? WfpNativeMethods.FWPM_FILTER_FLAG_PERSISTENT : 0,
                LayerKey = layerKey,
                SubLayerKey = WfpNativeMethods.OurSubLayerKey,
                Weight = new WfpNativeMethods.FwpValue
                {
                    Type = WfpNativeMethods.FWP_UINT64,
                    Value = weightPtr,
                },
                NumFilterConditions = 3,
                FilterCondition = conditionsPtr,
                Action = new WfpNativeMethods.FwpmAction { Type = action },
            };

            var descriptor = TryBuildProtectiveSd();
            var rc = WfpNativeMethods.FwpmFilterAdd0(_handle, ref filter, descriptor, out var id);

            if (descriptor != IntPtr.Zero)
            {
                LocalFree(descriptor);
            }

            if (rc != WfpNativeMethods.ERROR_SUCCESS)
            {
                LocalLog.Warning(
                    $"[WAG-WFP-003] Failed to add the DHCP block filter (0x{rc:X8}).");
                throw new WfpException("添加 DHCP 阻断过滤器失败", rc);
            }

            return id;
        }
        finally
        {
            Marshal.FreeHGlobal(conditionsPtr);
            Marshal.FreeHGlobal(weightPtr);

            if (namePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(namePtr);
            }

            if (descriptionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(descriptionPtr);
            }

            if (addressPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(addressPtr);
            }
        }
    }

    /// <summary>
    /// 加一条"按远端 IP 匹配"的过滤器（封禁 IP 用）。
    ///
    /// IPv4 走 <c>ALE_AUTH_CONNECT_V4</c>、IPv6 走 <c>ALE_AUTH_CONNECT_V6</c>；
    /// 条件值：IPv4 = FWP_UINT32（主机序），IPv6 = FWP_BYTE_ARRAY16（16 字节原样）。
    /// </summary>
    internal ulong AddIpFilter(
        Guid filterKey,
        string displayName,
        string? description,
        System.Net.IPAddress address,
        uint action,
        ulong weight,
        bool persistent,
        bool inbound = false)
    {
        ThrowIfDisposed();

        var isV4 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var layerKey = isV4
            ? (inbound
                ? WfpNativeMethods.LayerAleAuthRecvAcceptV4
                : WfpNativeMethods.LayerAleAuthConnectV4)
            : (inbound
                ? WfpNativeMethods.LayerAleAuthRecvAcceptV6
                : WfpNativeMethods.LayerAleAuthConnectV6);

        var bytes = address.GetAddressBytes();

        // IPv4 的 FWP_UINT32 是"主机序"：把点分地址当成一个大端整数存进 uint。
        // （POC 实测：这样写才能命中；反过来会完全匹配不上。）
        var v4Value = isV4
            ? (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3])
            : 0u;

        var namePtr = Marshal.StringToHGlobalUni(displayName);
        var descriptionPtr = description is null ? IntPtr.Zero : Marshal.StringToHGlobalUni(description);
        var weightPtr = Marshal.AllocHGlobal(sizeof(ulong));
        var conditionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNativeMethods.FwpmFilterCondition>());
        var addressPtr = IntPtr.Zero;

        try
        {
            Marshal.WriteInt64(weightPtr, unchecked((long)weight));

            WfpNativeMethods.FwpConditionValue value;

            if (isV4)
            {
                value = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_UINT32,
                    Value = (IntPtr)(long)v4Value,
                };
            }
            else
            {
                addressPtr = Marshal.AllocHGlobal(16);
                Marshal.Copy(bytes, 0, addressPtr, 16);

                value = new WfpNativeMethods.FwpConditionValue
                {
                    Type = WfpNativeMethods.FWP_BYTE_ARRAY16_TYPE,
                    Value = addressPtr,
                };
            }

            var condition = new WfpNativeMethods.FwpmFilterCondition
            {
                FieldKey = WfpNativeMethods.ConditionIpRemoteAddress,
                MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                ConditionValue = value,
            };
            Marshal.StructureToPtr(condition, conditionPtr, false);

            var filter = new WfpNativeMethods.FwpmFilter
            {
                FilterKey = filterKey,
                DisplayData = new WfpNativeMethods.FwpmDisplayData
                {
                    Name = namePtr,
                    Description = descriptionPtr,
                },
                Flags = persistent ? WfpNativeMethods.FWPM_FILTER_FLAG_PERSISTENT : 0,
                LayerKey = layerKey,
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

            var descriptor = TryBuildProtectiveSd();
            var rc = WfpNativeMethods.FwpmFilterAdd0(_handle, ref filter, descriptor, out var id);

            if (descriptor != IntPtr.Zero)
            {
                LocalFree(descriptor);
            }

            if (rc != WfpNativeMethods.ERROR_SUCCESS)
            {
                // 安全描述符不被接受时退回默认 SD —— 加固失败不能让规则建不出来。
                LocalLog.Warning($"[WAG-WFP-002] Failed to harden the IP filter; falling back to the default security descriptor: 0x{rc:X8}");
                rc = WfpNativeMethods.FwpmFilterAdd0(_handle, ref filter, IntPtr.Zero, out id);
            }

            if (rc != WfpNativeMethods.ERROR_SUCCESS)
            {
                throw new WfpException($"添加 IP 过滤器（{address}）", rc);
            }

            return id;
        }
        finally
        {
            if (addressPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(addressPtr);
            }

            Marshal.FreeHGlobal(conditionPtr);
            Marshal.FreeHGlobal(weightPtr);

            if (descriptionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(descriptionPtr);
            }

            Marshal.FreeHGlobal(namePtr);
        }
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

    /// <summary>按 key 删除；过滤器本来就不存在时返回 false（不算错误）。</summary>
    internal bool TryDeleteFilter(Guid filterKey)
    {
        ThrowIfDisposed();

        var key = filterKey;
        var rc = WfpNativeMethods.FwpmFilterDeleteByKey0(_handle, ref key);

        return rc switch
        {
            WfpNativeMethods.ERROR_SUCCESS => true,
            WfpNativeMethods.FWP_E_FILTER_NOT_FOUND => false,
            _ => throw new WfpException($"删除过滤器 {filterKey}", rc),
        };
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
    /// <param name="description">说明字段。2.0 的规则内容就存在这里（见 <see cref="WfpRule.Description"/>）；不需要时传 null。</param>
    /// <param name="exePath">目标程序的可执行文件完整路径。</param>
    /// <param name="layerKey">要挂到哪一层（V4 / V6 各挂一条）。</param>
    /// <param name="action">动作，用 <see cref="WfpNativeMethods.FWP_ACTION_BLOCK"/> 或 <see cref="WfpNativeMethods.FWP_ACTION_PERMIT"/>。</param>
    /// <param name="weight">同一子层内的权重，数值大的优先。</param>
    /// <param name="persistent">是否持久化（跨重启保留）。动态会话里必须为 false。</param>
    internal ulong AddAppIdFilter(
        Guid filterKey,
        string displayName,
        string? description,
        string exePath,
        Guid layerKey,
        uint action,
        ulong weight,
        bool persistent)
        => AddFilterCore(filterKey, displayName, description, layerKey, action, weight, persistent, exePath);

    /// <summary>
    /// 加一条**带精细化范围**的程序规则（协议 / 远端端口 / 网络位置）。
    /// 范围里全是「任意」时等价于普通的程序规则。
    /// </summary>
    internal ulong AddScopedAppIdFilter(
        Guid filterKey,
        string displayName,
        string? description,
        string exePath,
        Guid layerKey,
        uint action,
        ulong weight,
        bool persistent,
        RuleScope scope)
        => AddFilterCore(
            filterKey, displayName, description, layerKey, action, weight, persistent, exePath, scope);

    /// <summary>
    /// 加一条**不带任何条件**的过滤器 —— 它会匹配该层上的**所有**流量。
    ///
    /// 严格模式的"阻止全部"用的就是它：放在权重 0，上面再挂白名单的放行过滤器（权重更高）。
    /// 注意它必须建在**动态会话**里：这是"进程退出即自动撤销"的前提。
    /// </summary>
    internal ulong AddBlockAllFilter(
        Guid filterKey,
        string displayName,
        Guid layerKey,
        uint action,
        ulong weight,
        bool persistent = false)
        => AddFilterCore(filterKey, displayName, null, layerKey, action, weight, persistent, null);

    /// <summary>
    /// 加过滤器的唯一实现。<paramref name="exePath"/> 为 null 时不带条件（匹配全部）。
    /// </summary>
    private ulong AddFilterCore(
        Guid filterKey,
        string displayName,
        string? description,
        Guid layerKey,
        uint action,
        ulong weight,
        bool persistent,
        string? exePath,
        RuleScope? scope = null)
    {
        ThrowIfDisposed();

        var appIdPtr = IntPtr.Zero;
        var weightPtr = IntPtr.Zero;
        var namePtr = IntPtr.Zero;
        var descriptionPtr = IntPtr.Zero;
        var conditionPtr = IntPtr.Zero;
        var rangePtr = IntPtr.Zero;

        try
        {
            weightPtr = Marshal.AllocHGlobal(sizeof(ulong));
            Marshal.WriteInt64(weightPtr, unchecked((long)weight));

            namePtr = Marshal.StringToHGlobalUni(displayName);

            if (description is not null)
            {
                descriptionPtr = Marshal.StringToHGlobalUni(description);
            }

            var conditions = new List<WfpNativeMethods.FwpmFilterCondition>();

            if (exePath is not null)
            {
                var appIdResult = WfpNativeMethods.FwpmGetAppIdFromFileName0(exePath, out appIdPtr);
                if (appIdResult != WfpNativeMethods.ERROR_SUCCESS)
                {
                    throw new WfpException($"取程序身份（{exePath}）", appIdResult);
                }

                conditions.Add(new WfpNativeMethods.FwpmFilterCondition
                {
                    FieldKey = WfpNativeMethods.ConditionAleAppId,
                    MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                    ConditionValue = new WfpNativeMethods.FwpConditionValue
                    {
                        Type = WfpNativeMethods.FWP_BYTE_BLOB_TYPE,
                        Value = appIdPtr,
                    },
                });
            }

            // ---- 2.5 的精细化条件 ----
            if (scope is { IsAny: false })
            {
                if (scope.Protocol != RuleProtocol.Any)
                {
                    conditions.Add(new WfpNativeMethods.FwpmFilterCondition
                    {
                        FieldKey = WfpNativeMethods.ConditionIpProtocol,
                        MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                        ConditionValue = new WfpNativeMethods.FwpConditionValue
                        {
                            Type = WfpNativeMethods.FWP_UINT8,
                            Value = (IntPtr)(int)scope.Protocol,
                        },
                    });
                }

                if (scope.HasPort)
                {
                    if (scope.IsSinglePort)
                    {
                        conditions.Add(new WfpNativeMethods.FwpmFilterCondition
                        {
                            FieldKey = WfpNativeMethods.ConditionIpRemotePort,
                            MatchType = WfpNativeMethods.FWP_MATCH_EQUAL,
                            ConditionValue = new WfpNativeMethods.FwpConditionValue
                            {
                                Type = WfpNativeMethods.FWP_UINT16,
                                Value = (IntPtr)scope.PortFrom,
                            },
                        });
                    }
                    else
                    {
                        // 端口范围：条件值类型是 FWP_RANGE_TYPE，指向一个 FWP_RANGE0。
                        rangePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNativeMethods.FwpRange>());

                        var range = new WfpNativeMethods.FwpRange
                        {
                            Low = new WfpNativeMethods.FwpValue
                            {
                                Type = WfpNativeMethods.FWP_UINT16,
                                Value = (IntPtr)scope.PortFrom,
                            },
                            High = new WfpNativeMethods.FwpValue
                            {
                                Type = WfpNativeMethods.FWP_UINT16,
                                Value = (IntPtr)scope.PortTo,
                            },
                        };

                        Marshal.StructureToPtr(range, rangePtr, false);

                        conditions.Add(new WfpNativeMethods.FwpmFilterCondition
                        {
                            FieldKey = WfpNativeMethods.ConditionIpRemotePort,
                            MatchType = WfpNativeMethods.FWP_MATCH_RANGE,
                            ConditionValue = new WfpNativeMethods.FwpConditionValue
                            {
                                Type = WfpNativeMethods.FWP_RANGE_TYPE,
                                Value = rangePtr,
                            },
                        });
                    }
                }
            }

            var conditionCount = (uint)conditions.Count;

            if (conditions.Count > 0)
            {
                var size = Marshal.SizeOf<WfpNativeMethods.FwpmFilterCondition>();
                conditionPtr = Marshal.AllocHGlobal(size * conditions.Count);

                for (var i = 0; i < conditions.Count; i++)
                {
                    Marshal.StructureToPtr(
                        conditions[i], IntPtr.Add(conditionPtr, i * size), false);
                }
            }

            var filter = new WfpNativeMethods.FwpmFilter
            {
                FilterKey = filterKey,
                DisplayData = new WfpNativeMethods.FwpmDisplayData
                {
                    Name = namePtr,
                    Description = descriptionPtr,
                },
                Flags = persistent ? WfpNativeMethods.FWPM_FILTER_FLAG_PERSISTENT : 0,
                LayerKey = layerKey,
                SubLayerKey = WfpNativeMethods.OurSubLayerKey,
                Weight = new WfpNativeMethods.FwpValue
                {
                    Type = WfpNativeMethods.FWP_UINT64,
                    Value = weightPtr,
                },
                NumFilterConditions = conditionCount,
                FilterCondition = conditionPtr,
                Action = new WfpNativeMethods.FwpmAction { Type = action },
            };

            var descriptor = TryBuildProtectiveSd();
            var rc = WfpNativeMethods.FwpmFilterAdd0(_handle, ref filter, descriptor, out var id);

            if (descriptor != IntPtr.Zero)
            {
                LocalFree(descriptor);
            }

            if (rc != WfpNativeMethods.ERROR_SUCCESS)
            {
                // 安全描述符不被接受时退回默认 SD —— 加固失败不能让规则建不出来。
                LocalLog.Warning($"[WAG-WFP-003] Failed to harden the filter; falling back to the default security descriptor: 0x{rc:X8}");
                rc = WfpNativeMethods.FwpmFilterAdd0(_handle, ref filter, IntPtr.Zero, out id);
            }

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

            if (rangePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(rangePtr);
            }

            if (namePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(namePtr);
            }

            if (descriptionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(descriptionPtr);
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

    /// <summary>
    /// 构造保护性 DACL：SYSTEM + 所有者（3.4）。
    ///
    /// 所有者 SID 来自受保护模式配置；读不到时退回旧的 SYSTEM + Administrators，
    /// 保证配置损坏的系统仍然可以管理，而不是“谁都删不掉”。
    /// </summary>
    internal static string BuildProtectiveSddl(string? ownerSid)
    {
        const string systemAce = "(A;;0xF01FF;;;SY)";

        // 对象的 Owner 必须显式设置，不能留成 BA（Administrators）：
        // Windows 会给对象 Owner 隐式 WRITE_DAC，如果 Owner 还是 BA，
        // 即使 DACL 里没有 BA，管理员仍能改 ACL 再删除。
        // 设成创建者自己（服务 = SYSTEM，CLI/自检 = 当前所有者）即可：
        // 创建者把 Owner 设成自己不需要额外特权。
        var creatorSid = GetCreatorSid();

        if (string.IsNullOrWhiteSpace(ownerSid))
        {
            return $"O:{creatorSid}G:SYD:P{systemAce}(A;;0xF01FF;;;BA)";
        }

        // 所有者就是 SYSTEM：不重复添加，也不需要 BA。
        if (string.Equals(ownerSid, "S-1-5-18", StringComparison.OrdinalIgnoreCase))
        {
            return $"O:{creatorSid}G:SYD:P{systemAce}";
        }

        return $"O:{creatorSid}G:SYD:P{systemAce}(A;;0xF01FF;;;{ownerSid})";
    }

    private static string? _creatorSid;

    private static string GetCreatorSid()
    {
        if (_creatorSid is not null)
        {
            return _creatorSid;
        }

        try
        {
            _creatorSid = WindowsIdentity.GetCurrent().User?.Value ?? "SY";
        }
        catch (Exception)
        {
            _creatorSid = "SY";
        }

        return _creatorSid;
    }

    private static string? _ownerSid;
    private static bool _ownerSidResolved;

    /// <summary>
    /// 读取所有者 SID（只读一次）。服务以 SYSTEM 运行，不能用当前进程身份。
    /// 失败返回 null，由调用方回退到 SYSTEM + Administrators。
    /// </summary>
    private static string? ResolveOwnerSid()
    {
        if (_ownerSidResolved)
        {
            return _ownerSid;
        }

        _ownerSidResolved = true;

        try
        {
            var config = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory).ReadConfig();

            if (!string.IsNullOrWhiteSpace(config.OwnerSid))
            {
                // 先验证格式：非法 SID 传给 ConvertStringSecurityDescriptor 只会失败，
                // 不如在这里就当作“读不到”。
                _ = new SecurityIdentifier(config.OwnerSid);
                _ownerSid = config.OwnerSid;
            }
        }
        catch (Exception ex)
        {
            LocalLog.Warning(
                "[WAG-WFP-007] Failed to read the owner SID; WFP objects keep SYSTEM + Administrators.", ex);
        }

        return _ownerSid;
    }

    /// <summary>
    /// 构造保护性安全描述符：SYSTEM + 所有者（3.4）。
    ///
    /// 3.0-c 修正：**只在创建对象时传入**（FwpmSubLayerAdd0 / FwpmFilterAdd0 的
    /// securityDescriptor 参数）。VM 实测“先创建、再 SetSecurityInfo”会把服务启动卡死，
    /// 创建时附带安全描述符才是标准且安全的方式。
    ///
    /// 失败返回 <see cref="IntPtr.Zero"/>（调用方退回默认 SD），绝不抛异常。
    /// </summary>
    private static IntPtr TryBuildProtectiveSd()
    {
        var ownerSid = ResolveOwnerSid();
        var descriptor = TryConvertSddl(BuildProtectiveSddl(ownerSid));

        if (descriptor != IntPtr.Zero)
        {
            return descriptor;
        }

        if (!string.IsNullOrWhiteSpace(ownerSid))
        {
            LocalLog.Warning(
                "[WAG-WFP-006] Failed to build the owner-only WFP security descriptor; falling back to SYSTEM + Administrators.");

            descriptor = TryConvertSddl(BuildProtectiveSddl(null));

            if (descriptor != IntPtr.Zero)
            {
                return descriptor;
            }
        }

        return IntPtr.Zero;
    }

    private static IntPtr TryConvertSddl(string sddl)
    {
        try
        {
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl,
                    SddlRevision1,
                    out var descriptor,
                    out _))
            {
                return descriptor;
            }

            LocalLog.Warning(
                $"[WAG-WFP-004] Failed to build the protective security descriptor; using the default SD (win32 {Marshal.GetLastWin32Error()}).");
        }
        catch (Exception ex)
        {
            LocalLog.Warning("[WAG-WFP-005] Exception while building the protective security descriptor; using the default SD.", ex);
        }

        return IntPtr.Zero;
    }

    private const uint SddlRevision1 = 1;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out int securityDescriptorSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);

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
