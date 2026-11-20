# 一键封锁 {#one-click-blocking}

告警会点名元凶，并附上封锁它的命令。封锁是一个单独的、需要显式确认的动作，使用它自己的**写 Token**（`CF_WRITE_TOKEN`，见[权限](permissions.md#write-token-cf_write_token)）；看守进程从不读取它。

```bash
flarehound block asn 207990 --action block --for 24h
flarehound block ip 45.13.7.9
flarehound block ip 45.13.7.0/24 --reason "scraper, 11-17 incident"
flarehound block country XX --action challenge
flarehound block ua "BadBot/1.0" --for 7d
flarehound unblock asn 207990
flarehound blocks              # everything blocked, attempts over 7 days, expiry
flarehound enforce             # optional without a console: lifts blocks whose --for has passed
```

配置了多个 zone 时，加上 `--zone NAME|ID`。

当[控制台](console.md#blocking-from-the-console)进程持有写 Token 时，同样的操作也能在控制台里完成——护栏、审阅、审计与读回完全相同，另有撤销和封前 / 封后对比。

## 目标与默认值 {#targets-and-defaults}

| 目标 | 接受 | 默认动作 | Cloudflare 对象 |
|---|---|---|---|
| `ip` | IPv4 / IPv6 地址或 CIDR（IPv4 不宽于 /8，IPv6 不宽于 /16） | 拦截（block） | 账户 IP 名单 `flarehound_block` + 规则 `flarehound-ip-block`（`ip.src in $flarehound_block`）；否则用表达式规则 |
| `asn` | `207990` 或 `AS207990` | 质询（challenge） | 规则 `(ip.geoip.asnum in {…}) and not cf.client.bot` |
| `country` | 两位 ISO 代码（另有 `T1` 表示 Tor） | 质询（challenge） | 规则 `(ip.geoip.country in {…}) and not cf.client.bot` |
| `ua` | User-Agent 子串，3–200 个字符 | 拦截（block） | 规则 `(http.user_agent contains "…" or …)` |

`--action` 取 `block` 或 `challenge`（托管质询）。ASN 与国家规则始终放行已验证机器人，所以封锁绝不会误伤搜索引擎。

## FlareHound 会动什么 {#what-flarehound-touches}

- 只动它自己的对象：每种目标类型与动作各一条自定义规则，命名为 `flarehound-<type>-<action>`（例如 `flarehound-asn-challenge`），IP 名单 `flarehound_block`，以及备注以 `flarehound:` 开头的 IP Access Rules。你的规则永远不会被修改或调整顺序。
- **FlareHound 规则放在哪里**（v1.16）：排在所有放行（skip）规则之后（你的服务和已核验爬虫仍然豁免），排在你的第一条质询或拦截规则之前（确认要封的目标不会先被质询一遍）。审阅时会显示位置（「inserted at #4, after «…» and before «Protected Pages» (managed_challenge)」），并读回核对。v1.16 之前创建、位置不符的 FlareHound 规则，会在下一次封锁时移动一次；之后再添加成员不会再移动它。
- **绕过警告**：拦截规则之前的每条放行规则，都会拿目标以及该目标最近 24 小时发送过的 User-Agent 去求值。如果某条规则确定会匹配，审阅时会显示一条红色警告并点出这条规则——这次封锁对该目标可能不起作用。
- 同一类型的目标合并进一条规则，所以自定义规则额度（Free 5 / Pro 20 / Business 100 / Enterprise 1,000，与你自己的规则共用）几乎不受影响。解封最后一个条目时会删除该规则，腾出名额。
- 表达式采用固定格式，以便读回。如果你手工把 FlareHound 规则改成它认不出的形状，FlareHound 会拒绝修改它。超过 4,096 个字符的规则会被拒绝。
- 配置了 `cloudflare.account_id` 且 Token 带 Account Filter Lists: Edit 时使用 IP 名单；否则 IP 放进表达式规则（仍然只占一条规则）。
- 自定义规则额度已满时，IP 与 ASN 退回到 **IP Access Rules**（不占额度，但没有条件逻辑——已验证机器人*不*豁免；IPv4 段只能是 /16 或 /24，IPv6 只能是 /48 或 /64）。国家与 User-Agent 没有退路。
- 以 Cloudflare 为准：当前的封锁每次都从 Cloudflare 读取。

## 确认步骤 {#the-confirmation-step}

在任何改动之前，FlareHound 先打印方案：zone、目标（ASN 带网络类型与名称；IP 带 [IP 归属地](configuration.md#geoip)，单个地址还带其所属网络与最近 24 小时的请求量）、动作、机制与额度、改后的规则表达式、目标在最近一个已落定小时相对昨天同一小时的超额流量中实测的占比（IP、ASN 与 UA；网段和国家无法测量）、到期时间，以及全部警告。然后只问一次 `Apply? [y/N]`。

护栏：

| 永不封锁 | 方式 |
|---|---|
| Cloudflare 的 IP 段 | 实时获取，内置一份后备副本 |
| 你的源站 IP | 从 zone 的 A / AAAA 记录读取；读不到 DNS 时拒绝 IP 封锁，除非加 `--skip-origin-check` |
| 私有、保留与文档用地址段 | 内置 |
| `blocking.never_block` | 你的 IP / CIDR |
| Cloudflare 的 ASN（13335、209242）与 `blocking.never_block_asns` | 拒绝 ASN 封锁 |

确认前显示的警告：

- 目标在最近一小时超额流量中占比 < 1%——封了它也解决不了异常。
- 住宅 / 移动 / 骨干 ASN（真实用户从这里上网），或类型未知的 ASN。
- 整个国家——波及面最大。
- User-Agent——极易伪造和轮换。
- 在默认为质询的地方选择了拦截。

**强确认：**以拦截（动作 `block`）封非机房 ASN 或任何国家时，需要重新输入一遍 ASN 号码或国家代码。`--confirm VALUE` 可以预先填好；`--yes` **不能**代替它。

应用之后，FlareHound 读回 Cloudflare 进行核验，写入一条审计记录（[归档](archive.md)中的 `block_events`），并打印撤销命令。

## 修改或解除封锁 {#changing-or-lifting-a-block}

- 对已经以相同动作封锁的目标再次封锁，什么也不做；动作不同时，必须先解封。
- `flarehound unblock <type> <value>` 询问一次（`--yes` 跳过），并通过读回核验。

## 到期：`--for` 与 `enforce` {#expiry-for-and-enforce}

`--for` 接受 Go 时长写法外加天数：`30m`、`24h`、`7d`。Cloudflare 没有原生的到期机制，所以到期时间存放在归档的审计日志里，由 FlareHound 自己解除到期的封锁（记为 `expire` 事件，操作者在控制台为 `system:expiry`，在 CLI 为 `ttl`）：

- **控制台**持有写 Token 时，每 5 分钟执行一轮到期处理（v1.16）。无需另外运行任何东西。
- **`flarehound enforce`** 在没有控制台时做同样的事。它需要写 Token，并且必须持续运行：

```bash
flarehound enforce                 # every 5 minutes (--interval), all zones
flarehound enforce --once          # one pass, e.g. from cron
```

告警里的一键命令默认带 `--for 24h`。不带 `--for` 时，封锁是永久的。

## 列表与尝试量 {#listing-and-attempts}

`flarehound blocks [--days 7]` 列出所有 FlareHound 封锁（IP 后面跟着其 IP 归属地，`203.0.113.7 [IN · India]`），包括动作、机制、最近 N 天的尝试量、开始时间、到期时间与原因。它会将 Cloudflare 与审计日志对账，并标出手工创建的封锁（没有审计记录）。日报同样会列出每条封锁在其窗口内的尝试量。尝试量来自防火墙事件。在没有该数据集的地方（Free 套餐），IP 封锁的尝试量由归档的 IP 榜近似得出——每小时在边缘被拦下的前 50 个 IP——并标为「≈ … (approx.)」，同时给出该 IP 最近一次上榜的小时（IP 在某小时未进前 50 就不计入）；其他目标类型显示 "n/a"。尝试停了再解除封锁，而不是等它安静下来。

**实时核对**（v1.16）：`LIVE 1h` 列——以及封锁页——显示实时查询的最近一小时，并带最后一次尝试的时间（「4 (last 09:07)」）。这一小时为空时，它会回看 3 小时找最后一次拦截，而不是只显示一个 0（「none landed yet; last 12:58 (33m ago)」，或「none in 3h」）。付费套餐统计的是封锁自身规则的防火墙事件——这些事件可能晚 30–60 分钟才进入数据集，所以核对结果还会说明事件数据到达了哪个时间点（「data to 12:59」）；Free 统计的是该目标被任意规则在边缘拦下的请求。

日报增加 **本周到期**：7 天内到期的封锁，标为 *仍在敲门——建议续期* 或 *已无尝试——到期将自动解除*。

## Docker {#docker}

持有写 Token 的控制台服务会自行解除到期封锁。没有控制台时，`docker-compose.yml` 中的 `admin` profile 会带着写 Token 运行 enforcer，与看守进程分开：

```yaml
  flarehound-admin:
    image: passport888/flarehound:latest
    profiles: ["admin"]
    restart: unless-stopped
    command: ["-config", "/app/config.json", "enforce"]
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN:-}
      CF_WRITE_TOKEN: ${CF_WRITE_TOKEN:-}
    volumes:
      - ./config.json:/app/config.json:ro
      - ./data:/app/data
```

```bash
docker compose --profile admin up -d
docker compose run --rm flarehound-admin -config /app/config.json block asn 207990 --for 24h
```

交互式确认需要 TTY；`docker compose run` 默认会提供。
