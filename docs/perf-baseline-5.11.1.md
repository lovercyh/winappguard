# 性能基线模板（5.11.1 → 5.12.0）

> 本文件是**采集模板**。数字必须在验收 VM 上跑出来再填入；
> 不要在没有测量的情况下宣布优化达标。

## 采集环境

| 项 | 值 |
|---|---|
| VM / 主机 | 待填 |
| CPU | 待填 |
| 内存 | 待填 |
| 磁盘 | 待填 |
| Windows 版本 | 待填 |
| Npcap | 待填 |
| Suricata | 待填 |
| 规则数量 | 待填 |
| 事件数量 | 待填 |

## 命令

```powershell
dotnet run --project tools\SelfCheck\SelfCheck.csproj -c Release -- `
  --perf --perf-iterations 300 --perf-threads 10 --perf-requests 100 `
  --perf-out perf-5.11.1.json
```

## 结果

| 场景 | requests | errors | p50 | p95 | p99 | bytes |
|---|---:|---:|---:|---:|---:|---:|
| S1 status | 待填 | | | | | |
| S2 rules.list | 待填 | | | | | |
| S3 query.traffic | 待填 | | | | | |
| S4 query.ids | 待填 | | | | | |
| S5 并发 10×100 | 1000 | | — | — | — | — |
| S8 空载 10s | — | — | — | — | — | CPU/工作集待填 |

## 服务日志

```text
WAG-PERF-IPC      慢命令（>200ms）
WAG-PERF-TAMPER   巡检耗时（>50ms）
WAG-PERF-STATUS   status 耗时（>40ms）
WAG-RULE-031      导入耗时 / engineOpens
```

## 结论

- 待填：哪一项是主要瓶颈；
- 待填：5.12 的优先级是否需要调整（M0 决策门）。
