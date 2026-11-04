# 第三方组件与许可证

WinAppGuard 5.0 整体按 **GNU General Public License v2.0** 发布，见根目录 `LICENSE`。
以下组件仍适用其自身许可证；它们不因项目整体改为 GPL-2.0 而被重新许可。

## Suricata 8.0.7

- 项目：https://github.com/OISF/suricata
- 许可证：GPL-2.0
- 随包文件：`Suricata-8.0.7-1-64bit.msi`（未修改的官方 Windows 安装包）
- 源码获取：见 `SURICATA-SOURCE-OFFER.txt`

## ET Open（Emerging Threats Open）

- 项目：https://rules.emergingthreats.net/open/
- 规则版本：Suricata 7.0.3 规则包（随包快照，非自动更新）
- 许可证：混合
  - sids `2000000–2799999`：BSD-3-Clause，见 `ET-BSD-License.txt`
  - sids `1–3464`、`100000000–100000908`：GPL-2.0，见 `ET-GPL-2.0.txt`
  - ET Pro 规则不随包
- 随包文件：`standard.rules`、`all.rules`、`emerging.rules.zip`、`ET-classification.config`

## Npcap

- 官方安装包：`npcap-1.90.exe`
- 许可证：见安装目录 `Npcap-LICENSE.txt`
- Npcap 不由 GPL-2.0 覆盖，仍适用其自身许可。

## 说明

- WinAppGuard 与 OISF、Proofpoint、Emerging Threats、Npcap 的开发方没有隶属或背书关系。
- 规则包和 Suricata 均为本地数据/程序，不会自动联网更新。
- Suricata 解包到 `WinAppGuard\suricata`，不注册独立服务，也不创建桌面快捷方式；
  卸载 WinAppGuard 时会随安装目录一起删除。
- 如需再分发本安装包，请保留本文件及上述许可证文本。
