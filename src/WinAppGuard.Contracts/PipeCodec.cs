using System.Buffers.Binary;
using System.Text.Json;

namespace WinAppGuard.Contracts;

/// <summary>
/// 管道消息的编解码：4 字节小端长度 + UTF-8 JSON。
///
/// 为什么不用 "一行一个 JSON"：JSON 里可以合法出现换行（格式化输出），
/// 按行切会切坏；长度前缀没有这个问题。
///
/// 上限 <see cref="ServiceProtocol.MaxMessageBytes"/> 是硬性的：
/// 任何一方收到超长消息都直接断开，不给"用大消息拖死服务"的机会。
/// </summary>
public static class PipeCodec
{
    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, ServiceProtocol.JsonOptions);

        if (payload.Length > ServiceProtocol.MaxMessageBytes)
        {
            throw new InvalidDataException(
                $"消息太长（{payload.Length} 字节，上限 {ServiceProtocol.MaxMessageBytes}）。");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);

        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>读一条消息；对方正常关闭时返回 null。</summary>
    public static async Task<T?> ReadAsync<T>(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];

        if (!await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return default;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);

        if (length <= 0 || length > ServiceProtocol.MaxMessageBytes)
        {
            throw new InvalidDataException(
                $"消息长度不合法：{length}（上限 {ServiceProtocol.MaxMessageBytes}）。");
        }

        var payload = new byte[length];

        if (!await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false))
        {
            throw new EndOfStreamException("消息体没有读完，连接被提前关闭。");
        }

        return JsonSerializer.Deserialize<T>(payload, ServiceProtocol.JsonOptions);
    }

    /// <summary>
    /// 3.1 协议 v2 的签名封套：
    /// [4 字节签名长度][签名 DER][4 字节请求长度][请求 JSON]。
    /// </summary>
    public static async Task WriteSignedAsync(
        Stream stream,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (signature.Length <= 0 || signature.Length > ServiceProtocol.MaxSignatureBytes)
        {
            throw new InvalidDataException(
                $"签名长度不合法：{signature.Length}（上限 {ServiceProtocol.MaxSignatureBytes}）。");
        }

        if (payload.Length <= 0 || payload.Length > ServiceProtocol.MaxMessageBytes)
        {
            throw new InvalidDataException(
                $"请求长度不合法：{payload.Length}（上限 {ServiceProtocol.MaxMessageBytes}）。");
        }

        var header = new byte[8];
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(0, 4), signature.Length);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4, 4), payload.Length);

        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(signature, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<SignedEnvelope> ReadSignedAsync(
        Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[8];

        if (!await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            throw new EndOfStreamException("签名封套没有开始就被关闭。");
        }

        var signatureLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(0, 4));
        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4, 4));

        if (signatureLength <= 0 || signatureLength > ServiceProtocol.MaxSignatureBytes)
        {
            throw new InvalidDataException(
                $"签名长度不合法：{signatureLength}（上限 {ServiceProtocol.MaxSignatureBytes}）。");
        }

        if (payloadLength <= 0 || payloadLength > ServiceProtocol.MaxMessageBytes)
        {
            throw new InvalidDataException(
                $"请求长度不合法：{payloadLength}（上限 {ServiceProtocol.MaxMessageBytes}）。");
        }

        var signature = new byte[signatureLength];
        var payload = new byte[payloadLength];

        if (!await ReadExactlyAsync(stream, signature, cancellationToken).ConfigureAwait(false)
            || !await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false))
        {
            throw new EndOfStreamException("签名封套没有读完，连接被提前关闭。");
        }

        return new SignedEnvelope(signature, payload);
    }

    private static async Task<bool> ReadExactlyAsync(
        Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;

        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                // 头都还没读完 → 对方只是断开，不算错误；读到一半 → 由调用方当成错误。
                return offset != 0
                    ? throw new EndOfStreamException("连接在消息中途被关闭。")
                    : false;
            }

            offset += read;
        }

        return true;
    }
}

/// <summary>3.1 协议 v2 的签名封套内容。</summary>
public sealed class SignedEnvelope
{
    public SignedEnvelope(byte[] signature, byte[] payload)
    {
        Signature = signature;
        Payload = payload;
    }

    public byte[] Signature { get; }

    public byte[] Payload { get; }
}
