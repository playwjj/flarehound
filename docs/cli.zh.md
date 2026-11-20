# 命令行 {#command-line}

```
flarehound [flags]              run the watchdog (or a one-off action)
flarehound <command> [args]     see `flarehound help`
```

## 看守参数 {#watchdog-flags}

这些参数写在命令**之前**。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `-config PATH` | `config.json` | 配置文件。 |
| `-once` | 关 | 对每个 zone 运行一次小时级检查，然后退出。 |
| `-daily` | 关 | 立即生成日报，然后退出（`schedule.daily_report_at` 为空时拒绝执行）。 |
| `-dry-run` | 关 | 把消息打印到标准输出而不发送；不写状态、不写告警历史，因此永远不会消耗窗口。 |
| `-backfill N` | `0` | 从 Cloudflare 归档最近 N 天（1–30）的小时窗口，然后退出。需要归档。 |
| `-version` | 关 | 打印版本号并退出。 |

不带 `-once`、`-daily` 或 `-backfill` 时，FlareHound 持续运行：先立即检查最新的已稳定窗口，然后按计划运行小时级看守和日报。每轮有 15 分钟超时，并在开始时重发队列中的通知。`SIGINT` / `SIGTERM` 会让它干净地退出。

```bash
flarehound -config config.json
flarehound -config config.json -once -dry-run
flarehound -config config.json -daily -dry-run
flarehound -config config.json -backfill 28
```

## 命令 {#commands}

| 命令 | Token | 页面 |
|---|---|---|
| `doctor` | 只读（+ 写，用于测试写 Token） | 自检——见下文 |
| `health [--file heartbeat] [--max-age D]` | — | 心跳新鲜时退出码为 0（[心跳](channels.md#heartbeat-dead-man-switch)） |
| `audit` | 只读 | [WAF 规则体检](audit.md) |
| `calibrate [--days 7]` | 只读 | [口径校准](archive.md#calibration) |
| `simulate --expr EXPR [--action block|challenge] [--days 7|1] [--date YYYY-MM-DD] [--before N] [--json]` | 只读 | [规则模拟器](simulator.md)——用近期流量回放草稿规则；不改动任何东西 |
| `block <ip|asn|country|ua> <value> […]` | 写 | [封锁](blocking.md) |
| `unblock <ip|asn|country|ua> <value> [--yes]` | 写 | [封锁](blocking.md) |
| `blocks [--days 7]` | 写 | [封锁](blocking.md#listing-and-attempts) |
| `enforce [--once] [--interval 5m]` | 写 | [封锁](blocking.md#expiry-for-and-enforce) |
| `rules list|add|edit|delete|move|backups|restore|log` | 写 | [规则变更](rules.md) |
| `ratelimit add` | 写 | [规则变更](rules.md) |
| `cache add` | 写 | [规则变更](rules.md) |
| `console [--listen ADDR]` | 只读（+ 写，可选） | 启动 [Web 控制台](console.md)；`--listen` 覆盖 `console.listen` |
| `console init-admin --user NAME [--email ADDR]` | — | 创建管理员账号（密码从终端输入或取自 `FLAREHOUND_ADMIN_PASSWORD`） |
| `console users` | — | 列出控制台账号 |
| `console reset-password --user NAME` | — | 设置新密码、解除锁定、结束所有会话（本地恢复） |
| `console reset-totp --user NAME` | — | 关闭某个账号的二次验证（本地恢复） |
| `geoip update [-o PATH]` | — | 下载最新的 DB-IP 国家库用于 [IP 归属地](configuration.md#geoip)，并原子替换（`-o` 写到其他位置；不需要配置中的 Token） |
| `help` | — | 打印命令用法 |

### `flarehound doctor` {#flarehound-doctor}

安装后首先运行它。它以只读方式打印：

- 版本号以及配置是否通过校验；已配置的渠道；是否设置了心跳 URL；
- 每个 zone：分析数据是否可达（附上一小时的请求数）、套餐能力（ASN 拆解、防火墙事件及其保留时长）、Worker 指标；
- **能力矩阵**——小时级看守、WAF 规则体检、口径校准、一键封锁、规则变更、缓存规则——逐项 ✓ 或 ✗，**并指出缺少的权限**；
- 最近评估过的窗口、任何未结束的异常、下一个小时轮次和日报时间、心跳距今时长、归档覆盖范围、每个较新指标的基线背后已测得的样本数（以及仍在基线积累中的指标还需多少天），以及发件箱中待发的消息；
- **存储**：数据目录里有什么——`archive.db`（及其 WAL）连同最早的小时快照，以及大规模清理是否会把空间归还给磁盘；`console.db`；JSONL 文件及其轮转副本；`charts/` 中的 PNG（数量、大小、最早时间）——这样缓慢的增长也能被看见；
- [IP 归属地](configuration.md#geoip) 库：已加载（类型、构建日期、文件日期、网段数）、未找到（该功能关闭——不是问题），或存在但无法使用（✗）。

缺少必需项时退出码为 1。写权限通过只读调用探测，因此编辑权限只有真正做一次变更才能证实。

位置参数在前，参数（flag）在后：`flarehound block asn 207990 --for 24h`。`-config` 既可以写在命令之前，也可以写在命令的参数之中。

## 命令参数 {#command-flags}

| 参数 | 默认值 | 适用命令 | 含义 |
|---|---|---|---|
| `--config PATH` | `config.json` | 全部 | 配置文件。 |
| `--zone NAME|ID` | — | 全部 | 要操作的 zone。配置了多个 zone 时，`block`、`unblock`、`blocks`、`rules`、`ratelimit`、`cache` 必须指定；`audit` 和 `calibrate` 默认作用于全部 zone；`enforce` 始终覆盖全部 zone。 |
| `--action ACTION` | 按目标而定 / 见右 | `block`、`rules`、`ratelimit` | `block`：`block` 或 `challenge`（ip/ua 默认 `block`，asn/country 默认 `challenge`）。`rules add/edit`：一个 Cloudflare 动作。`ratelimit add`：默认 `managed_challenge`。 |
| `--for DURATION` | 永久 | `block` | 临时封锁，例如 `30m`、`24h`、`7d`。需要归档。 |
| `--reason TEXT` | — | `block`、`unblock` | 记录在审计日志中。 |
| `--yes` | 关 | `block`、`unblock` | 跳过 y/N 提示。不能代替强确认。`rules`、`ratelimit`、`cache` 不接受此参数。 |
| `--confirm VALUE` | — | `block` | 预先输入的 ASN / 国家代码，用于强确认。 |
| `--skip-origin-check` | 关 | `block` | 即使无法读取 DNS 来保护源站 IP，也封锁该 IP。 |
| `--days N` | `7` | `blocks`、`calibrate` | `blocks` 的尝试量统计窗口；`calibrate` 测量的天数（1–365）。 |
| `--once` | 关 | `enforce` | 执行一遍后退出。 |
| `--interval DURATION` | `5m` | `enforce` | 两遍之间的间隔。 |
| `--phase NAME` | `custom` | `rules` | `custom`、`ratelimit` 或 `cache`。 |
| `--expr EXPR` | — | `rules`、`ratelimit`、`cache` | 规则表达式（Cloudflare 规则语言）。 |
| `--desc TEXT` | — | `rules`、`ratelimit`、`cache` | 规则描述（`rules add` 必填）。 |
| `--before N|ID` | — | `rules add/move`、`ratelimit add`、`cache add` | 放在第 N 条规则（位置）或指定 ID 的规则之前。 |
| `--last` | 关 | `rules move` | 移到末尾。 |
| `--disabled` | 关 | `rules add` | 创建为禁用状态。 |
| `--enabled true|false` | — | `rules edit` | 启用或禁用。 |
| `--path PATTERN` | — | `ratelimit add`、`cache add`、`rules add` | 带 `*` 通配符的路径模式，未给出 `--expr` 时转换为表达式。 |
| `--requests N` | `20` | `ratelimit add` | 每个 IP 每个周期的请求数。 |
| `--period SECONDS` | `10` | `ratelimit add` | 计数周期。 |
| `--timeout SECONDS` | `10` | `ratelimit add` | 处置持续时间。 |
| `--ttl DURATION` | `1d` | `cache add` | 边缘 TTL。 |
| `--observe DURATION` | 关 | `rules`、`ratelimit` | 变更后，在这段时间内观察该规则的防火墙事件。 |

## 退出码 {#exit-codes}

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 出错，或确认被拒绝（`aborted, nothing changed`） |
| 2 | 用法错误（未知命令、错误的参数或位置参数） |
