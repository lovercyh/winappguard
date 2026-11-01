using System.Text;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.5：DNS 线上的名称读取（支持压缩指针）。
/// DNS / LLMNR / mDNS / NBNS 的响应都用同一套压缩格式，统一放在这里，
/// 避免每个解析器各写一份、边界处理不一致。
/// </summary>
internal static class DnsWire
{
    /// <summary>
    /// 读取一个名称，返回下一个字段的偏移。
    /// 压缩指针最多跳 8 次、必须回退（防止恶意报文构造环）。
    /// </summary>
    /// <param name="baseOffset">报文头在原始缓冲里的起始偏移（压缩指针相对它计算）。</param>
    internal static bool TryReadName(
        ReadOnlySpan<byte> span,
        int offset,
        int limit,
        out string name,
        out int nextOffset,
        int baseOffset = 0)
    {
        name = string.Empty;
        nextOffset = offset;
        var labels = new List<string>(4);
        var cursor = offset;
        var jumped = false;
        var guard = 0;

        while (cursor < limit)
        {
            var lengthByte = span[cursor];

            if (lengthByte == 0)
            {
                cursor++;

                if (!jumped)
                {
                    nextOffset = cursor;
                }

                name = labels.Count == 0 ? "." : string.Join(".", labels);
                return true;
            }

            if ((lengthByte & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= limit || guard++ > 8)
                {
                    return false;
                }

                if (!jumped)
                {
                    nextOffset = cursor + 2;
                }

                var target = baseOffset + (((lengthByte & 0x3F) << 8) | span[cursor + 1]);

                // 指针必须往回跳：向前跳等于让报文自己指自己。
                if (target >= cursor)
                {
                    return false;
                }

                cursor = target;
                jumped = true;
                continue;
            }

            if ((lengthByte & 0xC0) != 0 || cursor + 1 + lengthByte > limit)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(span.Slice(cursor + 1, lengthByte)));
            cursor += lengthByte + 1;

            if (!jumped)
            {
                nextOffset = cursor;
            }
        }

        return false;
    }
}
