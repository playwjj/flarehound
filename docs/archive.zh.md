# 本地归档与口径校准 {#local-archive-calibration}

## 为什么要归档 {#why-an-archive}

Cloudflare 只保留约 31 天的 adaptive 分析数据（防火墙事件同样如此，Free 上则完全没有），原始日志是按量计费的附加服务。FlareHound 把每次检查的快照存入本地 SQLite 文件，建立起平台本身不保留的长期记忆。归档保存的是**聚合数据，从不保存单个请求**。

## 文件与内容 {#file-and-contents}

- 路径：`archive.file`，默认是数据目录中的 `archive.db`（与 `state_file` 放在一起，所以默认为 `data/archive.db`）。只有一个文件；备份它就是复制它。SQLite，WAL 模式，使用纯 Go 驱动。
- 可用 `archive.disabled: true` 关闭——但 `-backfill`、`block --for`（到期时间）和 [规则变更命令](rules.md)（备份与审计日志）都依赖它。

| 表 | 内容 | 保留期 |
|---|---|---|
| `snapshots` | 每个 zone 每个窗口一行（`hour`，以及来自日报的 `day`）：总量加上以 JSON 保存的完整查询集——缓存状态拆分、Top dynamic 路径、按规则的防火墙事件，以及（自 v1.14 起）Top 50 客户端 IP 及其 ASN、单独列出的 Cloudflare 已验证机器人地址（自 v1.14.1 起），和在边缘被拦下的 Top 50 IP | 小时：`archive.hourly_retention_days`（默认 400，最少 30）；日：永久 |
| `faces` | 每个 UA / ASN 在任意 Top 榜中首次和最近出现的时间，及其峰值计数 | 直到 `hourly_retention_days` 内未再出现（v1.18；此前为永久） |
| `alerts` | 每个产生了消息的决策：窗口、决策、指纹、发现 | `hourly_retention_days`（v1.18；此前为永久） |
| `block_events` | [一键封锁](blocking.md) 的审计日志：封锁、解封、到期 | 永久 |
| `rule_backups`, `rule_changes` | [规则变更模块](rules.md) 的快照与审计日志 | 永久 |
| `calibration_days` | 每日的 [口径校准](#calibration) 测量值 | 永久 |

每一轮小时看守都会写入当前窗口（为拆解额外做五次查询：缓存状态、dynamic 路径、防火墙事件、客户端 IP、在边缘被拦下的 IP）和基线窗口——基线只在尚未归档时才写入，因此更完整的副本永远不会被覆盖。每一轮还会以同一个截止点（`archive.hourly_retention_days` 天前）做清理：早于该点的小时快照、最近出现时间早于该点的面孔，以及窗口结束早于该点的已归档告警。日快照、封锁日志、规则备份和规则变更永不清理——它们很小，而审计正是它们存在的意义。归档读写错误只记录日志，绝不会让看守停下。

### 磁盘空间 {#disk-space}

SQLite 删除行后不会缩小文件；释放出的页会被后续插入复用，所以在稳态下（清理掉的与新增的一样多）文件大小会趋于平稳。**由 v1.18 或更高版本创建**的归档使用 `auto_vacuum=INCREMENTAL`：当一次清理删除 1,000 行或更多时——通常是在调低 `hourly_retention_days` 之后——释放的空间会还给磁盘，文件随之变小。**更早创建的归档保持原有模式**：它会趋于平稳但永远不会缩小，FlareHound 也不会重建它（如需手动缩小：停止服务后运行 `sqlite3 data/archive.db 'VACUUM'`）。`console.db` 同理。几 MB 大小的 WAL 文件（`archive.db-wal`）是 SQLite 正常的检查点大小，并非泄漏。`flarehound doctor` 会显示各文件的大小及其所用模式。

## 用途 {#what-it-is-used-for}

- **长基线**——一旦有 ≥ 20 个来自最近 28 天的同时段样本，量类发现就必须同时越过相对昨日的线**和**相对 4 周中位数的线（[检测](detection.md#long-baseline)）。在此之前，日报会显示积累进度。
- **面孔历史**——告警中的新面孔会标注「归档中首次出现」或「曾出现过：首次 / 最近 / 峰值」。在归档覆盖满 7 天之前，「首次出现」的说法会被替换为一行关于归档深度的说明（第一天时每个面孔都是新的）。
- 在比 Cloudflare 保留期更长的时间范围内统计**僵尸规则**和**封锁尝试量**。
- 为 `flarehound rules restore` 提供**规则备份**。

## 回填 {#backfill}

用 Cloudflare 仍保留的数据填充归档，而不必等上四周：

```bash
flarehound -config config.json -backfill 28
```

- `N` 为 1–30 天（Cloudflare 保留约 31 天）。
- 已归档的窗口会被跳过，因此可以放心重复运行。
- 回填的窗口只包含核心指标和 Top 榜。
- 节奏：大约每秒一次查询；每个窗口需要 `5 + Worker 数量 + path_rules 数量` 次查询，所以 28 天大约每个 zone 需要一小时。日志会打印预估时间和进度。

## 口径校准 {#calibration}

FlareHound 读取的是 Cloudflare 的 **adaptive** 分析数据（`httpRequestsAdaptiveGroups`），它是抽样的，并且还会计入 Worker 子请求和缓存操作。面板上的总量（`httpRequests1dGroups`）不计这些。因此 FlareHound 的数字通常会更高。所有阈值都以 FlareHound（adaptive）的口径计——拿告警和告警比，永远不要拿去和面板比。

```bash
flarehound calibrate --days 7          # all zones; read token only
flarehound calibrate --zone example.com
```

对每个 UTC 日，它对比：

| 指标 | 面板侧 | FlareHound 侧 |
|---|---|---|
| 请求数 | `requests` | adaptive `count`（附其平均抽样间隔） |
| 边缘缓存命中 | `cachedRequests` | `cacheStatus = hit` 的请求 |
| 边缘 5xx | `responseStatusMap` 中的 5xx | `edgeResponseStatus` 500–599 |

汇总结果取每日比值的**中位数**（不受个别反常日子影响）。缓存命中比值只计面板命中数 ≥ 100 的日子，5xx 比值只计面板 5xx ≥ 50 的日子。输出还会显示抽样率，并把 `min_count` 换算成面板口径。

| 结论 | 请求比值 | 含义 |
|---|---|---|
| FlareHound 计数更多 | > 1.15 | 符合预期：子请求和缓存操作 |
| FlareHound 计数更少 | < 0.85 | 不寻常：抽样过重或写入延迟；稍后重跑 |
| 一致 | ±15% 以内 | — |

当边缘 5xx 超过面板的 1.5 倍时，输出会指向缓存操作造成的记账假象（例如被记为 504 的 Cache API 未命中），并建议把它们列在 [`daily.artifacts`](configuration.md#daily) 下。

已测量的日子会存入归档，不会重复查询；汇总覆盖最新的 `max(--days, 7)` 个已存日子。`--days` 取值 1–365。日报会自动校准前一个 UTC 日，并附上一行比值。

!!! note "在一个实际运行的 Free zone 上实测"
    7 天中，FlareHound 统计的请求数约为面板的 **1.29 倍**（每日 1.23–1.35），边缘缓存命中约 1.09 倍，边缘 5xx 约 **1.84 倍**——5xx 多出的部分是缓存操作造成的记账假象。抽样保留了约 91% 的请求。
