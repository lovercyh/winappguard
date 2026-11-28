using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Core;

/// <summary>
/// 提权助手临时文件的读写（3.0-c 起）。
///
/// **为什么必须成对出现**：助手把响应写成 camelCase（<see cref="ServiceProtocol.JsonOptions"/>），
/// 界面读回时必须使用同一套选项。5.13 之前这里读文件用的是默认
/// <see cref="JsonSerializer"/> 选项（PascalCase、区分大小写），于是
/// <c>affected</c> / <c>skipped</c> / <c>failed</c> / <c>error</c> 全部读不到：
/// 界面显示“成功 + 0 条”，实际规则已经写入。
///
/// 5.16：提权链路用的临时文件改为唯一目录 + CreateNew + 拒绝重解析点，
/// 避免低权进程抢注/符号链接覆盖提权助手要写的响应文件。
/// </summary>
internal static class ElevatedIpcFile
{
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    internal static void WriteRequest(string path, ServiceRequest request)
        => WriteNew(path, JsonSerializer.Serialize(request, ServiceProtocol.JsonOptions));

    internal static ServiceRequest? ReadRequest(string path)
        => JsonSerializer.Deserialize<ServiceRequest>(
            ReadText(path),
            ServiceProtocol.JsonOptions);

    internal static void WriteResponse(string path, ResponsePayload response)
        => WriteNew(
            path,
            JsonSerializer.Serialize(
                response, response.GetType(), ServiceProtocol.JsonOptions));

    internal static ResponsePayload? ReadResponse(string path, Type type)
        => JsonSerializer.Deserialize(
            ReadText(path),
            type,
            ServiceProtocol.JsonOptions) as ResponsePayload;

    private static void WriteNew(string path, string json)
    {
        EnsureNotReparsePoint(path);

        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough);

        using var writer = new StreamWriter(stream, Utf8);
        writer.Write(json);
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }

    private static string ReadText(string path)
    {
        EnsureNotReparsePoint(path);
        return File.ReadAllText(path, Encoding.UTF8);
    }

    private static void EnsureNotReparsePoint(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var attributes = File.GetAttributes(path);

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"提权 IPC 临时文件是重解析点，已拒绝：{path}");
        }
    }
}
