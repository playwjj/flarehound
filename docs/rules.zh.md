# 规则变更 {#rule-changes}

第一次接触 WAF 规则？先读 [WAF 入门](waf-guide.md)，从规则配方开始。

执行模块把规则变更——包括告警里的质询、限速与缓存建议——应用到三个 Cloudflare phase：

| `--phase` | Cloudflare phase | 写 Token 权限 |
|---|---|---|
| `custom`（默认） | `http_request_firewall_custom`——自定义（WAF）规则 | Zone → WAF: Edit |
| `ratelimit` | `http_ratelimit`——限速规则 | Zone → WAF: Edit |
| `cache` | `http_request_cache_settings`——缓存规则 | Zone → Cache Rules: Edit |

它与[封锁](blocking.md)使用同一枚独立的写 Token（`CF_WRITE_TOKEN`），并需要[归档](archive.md)来存放备份与审计日志。配置了多个 zone 时，加上 `--zone NAME|ID`。

## 命令 {#commands}

```bash
flarehound rules list [--phase custom|ratelimit|cache]      # each rule with a plain-words explanation
flarehound rules recipes                                     # ready-made rules, explained
flarehound rules recipe NAME [--path P] [--action A] [--ips IPS] [--asns ASNS] [--header NAME --secret-env VAR] [--skip SCOPES]
flarehound rules add --action ACTION --expr EXPR --desc TEXT [--before N|ID] [--disabled] [--skip SCOPES]
flarehound rules edit N|ID [--expr EXPR] [--action ACTION] [--desc TEXT] [--enabled true|false]
flarehound rules delete N|ID
flarehound rules move N|ID (--before N|ID | --last)
flarehound rules backups                  # snapshots taken before each change
flarehound rules restore BACKUP_ID        # put a phase back as it was
flarehound rules log                      # execution audit log
flarehound ratelimit add --path PATTERN [--requests 20 --period 10 --timeout 10 --action managed_challenge]
flarehound cache add --path PATTERN [--ttl 1d]
```

- `N` 是规则在 `rules list` 中的位置；`ID` 是 Cloudflare 规则 ID（或它的 `ref`）。
- `--path` 接受带 `*` 通配符的模式，并转换成表达式（`/x` → `eq`，`/x*` → `starts_with`，其他含 `*` 的模式 → `wildcard`）；`--expr` 则直接接受完整表达式。
- `rules add` 需要 `--action`（Cloudflare 动作，如 `block` 或 `managed_challenge`）、`--expr`（或 `--path`）以及 `--desc`。
- **放行规则**（`--action skip`）必须说明跳过什么：`--skip rules`（其后的自定义规则——默认）、`ratelimit`、`managed`（托管规则）、`bots`（超级机器人对抗模式）、`legacy`（安全级别、浏览器完整性检查、UA 拦截、zone lockdown……），可逗号组合。FlareHound 会构造 Cloudflare 要求的 `action_parameters`；把放行规则改成其他动作时会移除它们。
- **规则配方**根据少量输入构造一条完整的规则，并按「放行 → 拦截 → 质询」的顺序放置：`protect-paths`、`ratelimit-paths`、`allow-service`、`allow-verified-bots`、`challenge-cloud-on-paths`。每个配方在常规确认之前，先打印它做什么、为什么、这条规则的白话解释以及注意事项。密钥请求头的值从 `--secret-env` 指定的环境变量读取，绝不从命令行读取。见 [WAF 入门](waf-guide.md#recipes)。
- `ratelimit add` 构造一条按 IP 的规则（按 IP 与数据中心计数）：每 `--period` 秒 `--requests` 次，处置持续 `--timeout` 秒，默认动作 `managed_challenge`。
- `cache add` 构造一条规则，使匹配的请求可被缓存，并以边缘 TTL 覆盖源站设置（`--ttl`，默认 `1d`；Go 时长写法或 `Nd`）。
- `--observe 5m`（自定义规则与限速规则的变更）会在之后观察被改规则的防火墙事件并报告计数。零只表示「还没有匹配的流量或尚未入库」；在没有防火墙事件的套餐上会跳过。

示例：

```bash
flarehound rules add --action managed_challenge \
  --expr 'starts_with(http.request.uri.path, "/login")' --desc "challenge login" --before 1
flarehound rules edit 3 --enabled false
flarehound rules move 3 --last
flarehound ratelimit add --path '/rank' --requests 20 --period 10
flarehound cache add --path '/assets/*' --ttl 1d
```

## 安全 {#safety}

每次变更都走相同的步骤：

1. **展示**完整的变更：添加时展示全部字段与插入位置，编辑时逐字段展示 `old → new`，删除时展示整条规则，移动时展示位置，恢复时展示每一条回来 / 被移除 / 被修改 / 被移动的规则。同时打印警告（例如插在已有规则之前、停用或删除一项防护）。
2. 以 `y/N` **确认**。刻意**没有 `--yes`**——传了会报错——也没有批量模式。
3. 先**备份**整个 phase，与 Cloudflare 返回的完全一致：写入归档（`rule_backups`），并写入数据目录下的 `backups/<zone>/<phase>-<time>-v<version>.json`（权限 0600）。
4. **应用**，然后**读回**，比对这次变更设置的每个字段以及规则的位置（Cloudflare 自行添加的字段不算差异）。不一致时报告为错误，并附上恢复命令。
5. **记录**到只追加的 `rule_changes` 表：时间、phase、操作、规则、变更前 / 后的 JSON、备份 ID、是否核验通过、详情（包括 API 拒绝）。用 `flarehound rules log` 查看。

护栏：

- 表达式在发送之前，先用 FlareHound 自带的规则语言解析器在本地做语法检查。
- 添加前按套餐检查额度：

| Phase | Free | Pro | Business | Enterprise |
|---|---|---|---|---|
| 自定义规则 | 5 | 20 | 100 | 1,000 |
| 限速规则 | 1 | 2 | 5 | 100 |
| 缓存规则 | 10 | 25 | 50 | 300 |

- 在 Free 上，限速周期与处置超时都必须是 10 秒。
- 封锁模块自有的规则（`flarehound-` 前缀）不能在这里修改——请用 `block` / `unblock`。
- 规则以原始 JSON 处理，所以 FlareHound 没有建模的字段（放行参数、限速细节、日志设置……）在编辑和恢复后都会保留。
- 新规则会得到一个以 `fhx-` 开头的 `ref`，读回时用它来定位。

## 恢复 {#restore}

`flarehound rules restore BACKUP_ID` 用快照替换整个 phase。它会先做一次新的备份，所以恢复本身也可以撤销；并且与其他变更一样经过确认与核验。每次成功的变更都会打印撤销命令：

```
Done — … (verified by read-back). Backup #12: data/backups/example.com/custom-20261117-091500-v7.json
Undo: flarehound rules restore 12
```

Cloudflare 按 `ref` 匹配规则：在一次实测中，带 `ref` 的规则在整个 phase 恢复后**保留了原 ID**，所以它们的命中历史得以延续。如果备份中有不带 `ref` 的规则，FlareHound 会警告它们可能得到新的 ID。恢复一个 phase 也会恢复其中 FlareHound 的封锁规则——之后请运行 `flarehound blocks` 进行对账。
