using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>恢复操作的结果。</summary>
/// <param name="FiltersDeleted">实际删除的过滤器条数。</param>
/// <param name="SublayerDeleted">删除之前子层是否存在（顺便说明删掉的是不是真的存在的东西）。</param>
/// <param name="WasAlreadyClean">事前是不是本来就干净（什么都没有）。</param>
internal sealed record WfpRecoveryReport(
    int FiltersDeleted,
    bool SublayerDeleted,
    bool WasAlreadyClean)
{
    /// <summary>给用户/日志看的一句话。</summary>
    internal string Describe() => WasAlreadyClean
        ? "没有发现本程序留在 WFP 里的任何对象，系统本来就是干净的。"
        : $"已删除 {FiltersDeleted} 条过滤器，并删除本程序的子层。";
}

/// <summary>
/// 2.0 的「恢复」：删光本程序在 WFP 里留下的**全部**对象。
///
/// ==================== 它为什么必须存在 ====================
/// 2.0 的 block 在最高权重的子层里，能压过 Windows 防火墙的 allow。
/// 万一程序在"默认拒绝"或"严格模式"中途死掉，用户需要一条**不依赖界面**的命令
/// 把机器恢复原状 —— 这就是 <c>--recover</c>。
///
/// ==================== 边界 ====================
/// 只碰两样东西：本程序子层 GUID 下的过滤器、以及这个子层本身。
/// **不碰 Windows 防火墙的规则**（那些由迁移流程负责），也不碰别的软件或系统
/// 在 WFP 里建的任何对象 —— 枚举时按子层 GUID 过滤，别的一律不删。
///
/// 顺序必须是「先删过滤器、再删子层」：子层被引用时删不掉
/// （<c>FWP_E_IN_USE 0x8032000A</c>，实测踩过）。
/// 操作是幂等的：本来就干净时返回 0，不报错。
/// </summary>
internal static class WfpRecovery
{
    /// <summary>执行恢复。失败时抛 <see cref="WfpException"/>（调用方负责告诉用户）。</summary>
    internal static WfpRecoveryReport Recover()
    {
        using var engine = WfpEngine.Open();

        var sublayerExisted = !SublayerMissing(engine);
        var filtersDeleted = engine.DeleteAllOurFilters();

        // 子层不存在时 DeleteSublayer 内部按"成功"处理，所以不用再判断。
        engine.DeleteSublayer();

        return new WfpRecoveryReport(
            filtersDeleted,
            sublayerExisted,
            filtersDeleted == 0 && !sublayerExisted);
    }

    private static bool SublayerMissing(WfpEngine engine)
    {
        try
        {
            engine.ReadSublayer();
            return false;
        }
        catch (WfpException ex)
        {
            return ex.Code == WfpNativeMethods.FWP_E_SUBLAYER_NOT_FOUND;
        }
    }
}
