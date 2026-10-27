# Npcap 随包说明

- 版本：`npcap-1.90.exe`
- 来源：https://npcap.com/dist/npcap-1.90.exe
- SHA-256：`682B57E1C05EF375931975C9D6DED40888F4BFDF9F4B11571E654F962F1199B6`
- 签名者：`CN=Nmap Software LLC, O=Nmap Software LLC, ...`（发布时仍有效）

## 使用方式

- `WinAppGuardSetup.exe` 把**官方未修改**的安装包放在内置载荷里；
- 用户选择安装时，只启动官方 GUI，不静默安装、不修改安装包；
- 启动参数只锁定安装选项：

  ```text
  /winpcap_mode=disabled /loopback_support=disabled /dot11_support=disabled /admin_only=enforced
  ```

- 安装目录里保留 `Npcap-LICENSE.txt`；
- 不把 `wpcap.dll` / `npcap.sys` 拆出来单独复制。

## 授权说明

项目所有者已与 Nmap Software 沟通，确认可以随包分发**官方、未篡改**的安装包。
请保留书面沟通记录；如果 Npcap 版本或分发范围变化，需要重新确认授权。
