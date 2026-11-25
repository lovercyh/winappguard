# 性能基线模板（5.11.1 → 5.12.0）

> 本文件是**采集模板**。数字必须在验收 VM 上跑出来再填入；
> 不要在没有测量的情况下宣布优化达标。

## 采集环境

> 下面是**宿主桌面**的参考采样（服务 5.11.1，客户端 5.12.0），
> 不是验收 VM 的正式基线。VM 验收时必须重新跑一遍并替换此表。

| 项 | 值 |
|---|---|
| VM / 主机 | 宿主桌面（参考） |
| 服务版本 | 5.11.1 / 协议 v4 |
| CPU | 待填 |
| 内存 | 待填 |
| 磁盘 | 待填 |
| Windows 版本 | 待填 |
| Npcap | 1.85 |
| Suricata | 运行中 |
| 规则数量 | 10 |
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
| S1 status | 30 | 0 | 2.35 ms | 3.03 ms | 3.12 ms | 452 |
| S2 rules.list | 30 | 0 | 1.23 ms | 1.75 ms | 5021.28 ms | 320 |
| S3 query.traffic | 30 | 0 | 3.28 ms | 4.98 ms | 6.58 ms | 3247 |
| S4 query.ids | 30 | 0 | 8.31 ms | 13.95 ms | 18.38 ms | 39517 |
| S5 并发 4×20 | 80 | 0 | — | — | — | — |
| S8 空载 3s | — | — | — | — | — | 非管理员跳过 |

> S2 的 p99 出现了 5 秒级离群值，正好是 5.11.1 “巡检持锁”的典型症状；
> 5.12 的 H1 去锁后需要在同一环境复测，确认 p99 回落。
> S8 在非管理员下无法读取 SYSTEM 服务进程的 CPU，属于预期跳过。

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
