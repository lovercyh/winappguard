# ET Open 规则快照

来源：https://rules.emergingthreats.net/open/suricata-7.0.3/

- `emerging.rules.zip`：原始 ET Open 规则包（保留许可证文件）。
- `standard.rules`：5.0 默认档，按以下条件生成：
  - `signature_severity = Critical / Major`
  - `attack_target = Client_Endpoint`
  - 仅保留 `emerging-malware`、`emerging-exploit`、`emerging-exploit_kit`、
    `emerging-attack_response`、`emerging-web_client`、`emerging-user_agents`、
    `emerging-ta_abused_services`、`emerging-file_sharing`、`emerging-ja3`、
    `emerging-coinminer`、`emerging-dns`、`emerging-current_events`
  - 只保留明确 Windows 或未标注平台的规则
- `all.rules`：全量规则合并；移除了 9 条 Suricata 8 不支持的 `file.magic` 规则。

许可证：

- ET 规则 sids `2000000–2799999`：BSD-3-Clause，见 `BSD-License.txt`
- sids `1–3464`、`100000000–100000908`：GPL-2.0，见 `gpl-2.0.txt`
- ET Pro 规则不随包

不自动更新；更新时重新下载官方规则包并重新生成。
