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
/// 请求方向同理，统一放在这里，避免两边再各写一套序列化选项。
/// </summary>
internal static class ElevatedIpcFile
{
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    internal static void WriteRequest(string path, ServiceRequest request)
        => File.WriteAllText(
            path,
            JsonSerializer.Serialize(request, ServiceProtocol.JsonOptions),
            Utf8);

    internal static ServiceRequest? ReadRequest(string path)
        => JsonSerializer.Deserialize<ServiceRequest>(
            File.ReadAllText(path, Encoding.UTF8),
            ServiceProtocol.JsonOptions);

    internal static void WriteResponse(string path, ResponsePayload response)
        => File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                response, response.GetType(), ServiceProtocol.JsonOptions),
            Utf8);

    internal static ResponsePayload? ReadResponse(string path, Type type)
        => JsonSerializer.Deserialize(
            File.ReadAllText(path, Encoding.UTF8),
            type,
            ServiceProtocol.JsonOptions) as ResponsePayload;
}
