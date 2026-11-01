using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.5：LLMNR / NBNS / mDNS 报文解析（只取事务 ID、名称与 A/AAAA）。
///
/// LLMNR 与 mDNS 使用标准 DNS 线格式；NBNS 的问题名是 32 字节 first-level 编码。
/// 所有长度、计数、压缩指针都有上限，恶意报文只会被丢弃，不会越界或死循环。
/// </summary>
public static class NameResolutionParser
{
    private const int MaxQuestions = 4;
    private const int MaxAnswers = 32;
    private const int MaxAddresses = 16;

    public static bool TryParse(
        ReadOnlySpan<byte> payload,
        string protocol,
        DateTime timeUtc,
        string adapter,
        string sourceAddress,
        string destinationAddress,
        string? sourceMac,
        out NameMessage message)
    {
        message = null!;

        if (payload.Length < 12)
        {
            return false;
        }

        var transactionId = BinaryPrimitives.ReadUInt16BigEndian(payload);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload[4..]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(payload[6..]);
        var isResponse = (flags & 0x8000) != 0;

        if (questionCount > MaxQuestions || answerCount > 64)
        {
            return false;
        }

        string name;
        List<string> addresses;
        uint ttl;

        if (protocol == NameProtocols.Nbns)
        {
            if (!TryParseNbns(payload, questionCount, answerCount, out name, out addresses, out ttl))
            {
                return false;
            }
        }
        else if (!TryParseDnsLike(payload, questionCount, answerCount, out name, out addresses, out ttl))
        {
            return false;
        }

        name = name.Trim().TrimEnd('.').ToLowerInvariant();

        if (name.Length == 0)
        {
            return false;
        }

        message = new NameMessage
        {
            TimeUtc = timeUtc,
            Adapter = adapter,
            Protocol = protocol,
            SourceAddress = sourceAddress,
            DestinationAddress = destinationAddress,
            SourceMac = sourceMac,
            IsResponse = isResponse,
            TransactionId = transactionId,
            Name = name,
            Addresses = addresses.Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxAddresses).ToList(),
            Ttl = ttl,
        };

        return true;
    }

    private static bool TryParseDnsLike(
        ReadOnlySpan<byte> payload,
        ushort questionCount,
        ushort answerCount,
        out string name,
        out List<string> addresses,
        out uint ttl)
    {
        name = string.Empty;
        addresses = new List<string>();
        ttl = 0;

        var length = payload.Length;
        var cursor = 12;

        if (questionCount > 0)
        {
            if (!DnsWire.TryReadName(payload, cursor, length, out name, out cursor)
                || cursor + 4 > length)
            {
                return false;
            }

            cursor += 4;

            for (var i = 1; i < questionCount; i++)
            {
                if (!DnsWire.TryReadName(payload, cursor, length, out _, out cursor)
                    || cursor + 4 > length)
                {
                    return false;
                }

                cursor += 4;
            }
        }

        string? firstAnswerName = null;

        for (var i = 0; i < answerCount && i < MaxAnswers; i++)
        {
            if (!DnsWire.TryReadName(payload, cursor, length, out var answerName, out cursor)
                || cursor + 10 > length)
            {
                break;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(payload[cursor..]);
            var answerTtl = BinaryPrimitives.ReadUInt32BigEndian(payload[(cursor + 4)..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(payload[(cursor + 8)..]);
            cursor += 10;

            if (cursor + dataLength > length)
            {
                break;
            }

            if (firstAnswerName is null && answerName.Length > 0 && answerName != ".")
            {
                firstAnswerName = answerName;
            }

            if (type == 1 && dataLength == 4)
            {
                addresses.Add(new IPAddress(payload.Slice(cursor, 4)).ToString());
                ttl = ttl == 0 ? answerTtl : Math.Min(ttl, answerTtl);
            }
            else if (type == 28 && dataLength == 16)
            {
                addresses.Add(new IPAddress(payload.Slice(cursor, 16)).ToString());
                ttl = ttl == 0 ? answerTtl : Math.Min(ttl, answerTtl);
            }

            cursor += dataLength;
        }

        if (name.Length == 0 || name == ".")
        {
            name = firstAnswerName ?? string.Empty;
        }

        return true;
    }

    private static bool TryParseNbns(
        ReadOnlySpan<byte> payload,
        ushort questionCount,
        ushort answerCount,
        out string name,
        out List<string> addresses,
        out uint ttl)
    {
        name = string.Empty;
        addresses = new List<string>();
        ttl = 0;

        var length = payload.Length;
        var cursor = 12;

        if (questionCount > 0)
        {
            // 0x20 + 32 字节编码名称 + 0x00 结尾。
            if (cursor + 34 > length || payload[cursor] != 0x20)
            {
                return false;
            }

            name = DecodeNbnsName(payload.Slice(cursor + 1, 32));
            cursor += 33;

            if (cursor + 1 + 4 > length)
            {
                return false;
            }

            cursor += 1 + 4;
        }

        for (var i = 0; i < answerCount && i < MaxAnswers; i++)
        {
            // 应答名通常是指向问题名的压缩指针。
            if (!DnsWire.TryReadName(payload, cursor, length, out _, out cursor)
                || cursor + 10 > length)
            {
                break;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(payload[cursor..]);
            var answerTtl = BinaryPrimitives.ReadUInt32BigEndian(payload[(cursor + 4)..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(payload[(cursor + 8)..]);
            cursor += 10;

            if (cursor + dataLength > length)
            {
                break;
            }

            if (type == 0x0001 && dataLength == 4)
            {
                addresses.Add(new IPAddress(payload.Slice(cursor, 4)).ToString());
                ttl = ttl == 0 ? answerTtl : Math.Min(ttl, answerTtl);
            }

            cursor += dataLength;
        }

        return name.Length > 0;
    }

    /// <summary>NBNS 的 32 字节 first-level 编码 → 15 字符名称（去掉填充）。</summary>
    private static string DecodeNbnsName(ReadOnlySpan<byte> encoded)
    {
        var chars = new char[16];

        for (var i = 0; i < 16; i++)
        {
            var high = encoded[i * 2] - (byte)'A';
            var low = encoded[i * 2 + 1] - (byte)'A';

            if (high is < 0 or > 15 || low is < 0 or > 15)
            {
                return string.Empty;
            }

            chars[i] = (char)((high << 4) | low);
        }

        return new string(chars, 0, 15).TrimEnd('\0', ' ');
    }
}
