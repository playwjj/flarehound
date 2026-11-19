<p align="center">
  <img src="https://raw.githubusercontent.com/playwjj/flarehound/main/docs/logo.png" alt="FlareHound logo" width="180">
</p>

# FlareHound

[English](README.md) | 中文

**一个自托管的流量控制台与看守工具，服务于 Cloudflare 后面的网站。** 它用一个只读令牌轮询 Cloudflare Analytics API，逐小时检测流量异常，按路径 / ASN / User-Agent / 缓存状态拆解，给你一份简短的大白话报告——结论先行，附证据和建议动作——只在真的有事需要你关注时才发。

Cloudflare 给你数据，FlareHound 给你结论。

> 状态：**v1.16.2**——新指标在基线攒够实测天数前不报警（控制台显示「基线积累中」）；边缘 52x 的判别统一用于告警、tile 与报告（Worker 记账底量 vs 真故障）；到期封锁由控制台自动解除；封锁规则插在 skip 规则之后、挑战规则之前，审阅时提示可能被 skip 放行；每条封锁的近 1 小时实时核对、Free 套餐的近似尝试量；Worker CPU 告警自带辨伪（P50 / P99 / 调用量）；面向 VPS 站的源站视角（源站不可达 52x、源站延迟 P95、5xx 比率与状态拆分）；IP 榜（谁在持续敲门：最近一小时与 24 小时；已验证机器人折叠、网段合并汇总）、下钻中显示客户端 IP；「现在什么在涨」：被封锁榜、与昨天对比的趋势带、实时面孔；SMTP 端口被封时改走 HTTPS 发邮件（Resend）；按 zone 的 WAF 审计覆盖；跨 zone 首页、日报中的封锁裁决、被规则覆盖的面孔标记、审计/规则快照；控制台内设置（通知渠道带测试发送、告警线带回放预览、已知面孔、网络命名）；控制台支持英文与中文；WAF 基础、规则配方与大白话规则说明；实时小时与涨跌榜下钻；Web 控制台内封锁、撤销、封前/封后对比、只读快照，以及 Google / GitHub 登录；「标为已知」改为紧凑链接。文档：**https://playwjj.github.io/flarehound/** · 更新日志：[CHANGELOG.md](CHANGELOG.md)
>
> **方向：** 内置 Web 控制台（自 v1.3 起）是产品的中心——实时涨跌、新面孔、对照长期基线的历史、WAF 审计与规则、设置，以及带按账号审计的控制台内封锁。通知退为提醒层，把你带到控制台来。见 [Web 控制台改版说明](docs/web-console-revision.md)。
>
> 检测模型、阈值与告警纪律移植自一次真实事件响应（2026-11-17 的住宅代理爬虫洪水）。

## 为什么

- 爬虫洪水可以从早上 08:00 开始烧 Workers CPU 好几个小时，而日报——或者账单——还什么都看不出来。
- Cloudflare 自家的智能异常工具大多在 Enterprise 套餐上。Pro / Business / Free 用户拿到的只有原始仪表盘。
- 一般的可用性监控只管*网站是否在线*，不管*你的流量在干什么*。

FlareHound 看的是流量本身：

- **逐小时异常看守**——刚结束的整点小时对照昨天同小时：zone 请求数、未缓存（`dynamic`）响应、源站 5xx、源站可达性与延迟（面向 VPS + Cloudflare 代理的站点）、Worker 调用量与 CPU P50。
- **先归因，再下结论**——每个尖峰先按路径、ASN、User-Agent、缓存状态拆开，「贵」的流量（Worker 渲染、回源）与便宜的边缘量分开报告。
- **新面孔检测**——突然冲进 Top 10、又不在昨天 Top 25 里的 User-Agent 与 ASN。
- **活着，且可证明**——每轮都写心跳（文件、JSONL、可选的 healthchecks.io 式 ping），容器带 `HEALTHCHECK`，看守死了绝不会看起来像网站很安静。
- **安静 by design**——没异常就没消息。同一个异常不会重复报警，除非再涨 25%；连续两轮干净后，只发一行「已恢复」。
- **只建议，永不代劳**——看守核心是只读的。它可以建议封某个 ASN 或挑战某个路径，附证据和预期影响，但绝不改你的 Cloudflare 配置。根据发现采取行动——封 IP、网段、ASN、国家或 User-Agent，或应用规则变更——是另一个独立的、需要显式确认的命令，用它自己的写令牌；看守进程本身永远不持有那个令牌。
- **一份 Cloudflare 不留的记忆**——Cloudflare 只保留约 31 天分析数据，原始日志还是按量收费的附加项。FlareHound 把每次检查快照进本地 SQLite 文件（`data/archive.db`，约 13 个月的小时快照，日汇总永久保留），补上平台缺失的长期记忆。归档满四周后，一个尖峰必须同时击败昨天*和*四周同小时中位数才会报警——一个反常的昨天不再能把你叫起来。新 ASN 与 User-Agent 会带首次出现日期报告，每条告警都存进历史表。

## 快速开始

发布镜像是多架构的（`linux/amd64`、`linux/arm64`），每次打 `v*` 标签时推到 Docker Hub，例如 `passport888/flarehound:1.12.0`。本仓库的 `docker-compose.yml` 拉取已发布镜像（也可以从源码本地构建，如果你更喜欢）。

```bash
docker compose up -d
```

1. 创建一个**只读**的 Cloudflare API 令牌（见下文）。
2. 把 `config.example.json` 复制为 `config.json`，填入你的 zone ID 与 Worker 名。
3. 把令牌放进环境变量——永远不要写进配置文件：

```bash
export CF_API_TOKEN=...
```

4. 把 `notify.webhook_url_env` 指向一个保存着「能接受 JSON POST 的任意端点」的环境变量（Telegram/Slack/Discord 的桥接也包括在内），或配置 Telegram 机器人。
   原生渠道（v0.8）：**Slack**、**Discord**、**企业微信**、**飞书/Lark**（可选签名密钥）和**电子邮件**（SMTP STARTTLS 或 TLS，或在 SMTP 端口被封时用 Resend 的 HTTPS API）——分别设置 `notify.slack_webhook_url_env`、`discord_webhook_url_env`、`wecom_webhook_url_env`、`feishu_webhook_url_env`（+ `feishu_secret_env`），或一个 `notify.email` 配置块；所有 URL 与密码都来自环境变量。长报告会按各服务的长度上限拆分，HTTP 200 里夹带的机器人错误也算失败（重试，然后排队）。
   想把告警接进你自己的工具链，就设置 `notify.jsonl_file`（如 `data/alerts.jsonl`）：每条消息追加为一行 JSON，带 `kind`、`zone`、`decision`、窗口、触发的 `rules` 与 `text`。
5. 选报告语言：`"report": {"language": "en"}` 或 `"zh"`（中文）。

可选：先把最近四周回填进本地归档（Cloudflare 保留约 31 天），这样四周基线从第一天起就生效，不用等到第五周。回填按约 1 次查询/秒限速，每个 zone 大约需要一小时：

```bash
flarehound -config config.json -backfill 28
```

检查安装——每个令牌能做什么、缺哪项权限都会点名：

```bash
flarehound -config config.json doctor
```

上线前先试运行——打印消息而不是发送：

```bash
flarehound -config config.json -once -dry-run    # 一次小时检查
flarehound -config config.json -daily -dry-run   # 今天的日报
```

### 一条消息长什么样

```
FlareHound · example.com — anomaly
Worker web calls +52.0%, Worker web CPU P50 +50.0%, dynamic +75.0%, zone requests +52.0% (+1 more)
Window 2026-11-17 08:00–09:00 (Asia/Shanghai)

Attribution:
- expensive (Worker/origin) 40,000 → 70,000 (+30,000); cheap (edge cache) 60,000 → 82,000 (+22,000)
- top dynamic paths: /rank 35,000 (was 20,000)
- AS207990 hits: /rank 35,000

Hypotheses:
- [high] Crawler/bot surge: new source AS207990 carries ~87% of the excess.
  Falsified if its path mix matches normal visitors and it comes from residential/mobile networks …

Sources are dispersed (top IP < 1% of the excess): per-IP blocking will not help — act at ASN or path level (challenge).

Suggestions (read-only — FlareHound never applies them; do it in the Cloudflare dashboard):
1. Block AS207990 (EXAMPLE-HOSTING-AS, hosting network)
   where: Security → WAF → Custom rules, action Block
   expression: (ip.geoip.asnum in {207990}) and not cf.client.bot
   why: 45,000 requests vs 0 yesterday, ~87% of the excess; a hosting network, where no human visitors are expected.
   gain: ~45,000 fewer requests per window, of which ~20,723 expensive (estimate)
   impact: anything legitimately running on that network (your own monitors, partner APIs, uptime checkers) is blocked too; …
   rollback: disable or delete the rule (takes effect in seconds)
```

**建议**自带证据、预期收益、影响范围、回滚办法和一份可直接粘贴的规则表达式。只有云/机房 ASN 才会被建议封锁；住宅、移动、骨干和未知网络得到的永远是*挑战*建议。证据太薄、或尖峰主要是便宜的边缘缓存流量时，不给建议。

### 令牌权限（只读）

在 *Cloudflare 控制台 → My Profile → API Tokens → Create Token → Custom token* 创建令牌：

- **Zone** → **Analytics: Read**（每个要监控的 zone）——这是看守唯一必需的权限。

可选附加项——只在启用对应功能时才授予：

- **Worker 指标**（配置里列了 `workers`）：加 **Account** → **Account Analytics: Read**。

- **WAF 规则审计**（v0.6）：给同一个令牌加 **Zone** → **WAF: Read**（可选 **Zone: Read** 做配额检查）。
- **一键封锁**（v0.5）与**规则变更**（v0.7）：另建一枚*独立的*写令牌——**Account** → **Account Filter Lists: Edit**；**Zone** → **WAF: Edit**（自定义规则；某些账户上还包括 IP Access Rules）、**DNS: Read**、**Zone: Read**（+ 改缓存规则用的 **Cache Rules: Edit**）。放进 `CF_WRITE_TOKEN`。永远不要把它并进只读令牌；看守进程永远不持有它。

权限名说明：自定义规则永远需要 **Zone → WAF**。IP Access Rules 随账户而异——有些账户归 Zone → WAF 管，有些归 **Firewall Services**，有些根本授予不了；它们是可选的，FlareHound 缺了也能降级工作。`flarehound doctor` 会显示你的令牌实际能摸到什么。

看守只调用 GraphQL Analytics（`api.cloudflare.com/client/v4/graphql`），所以 Analytics: Read 就够了；本 README 的旧版本还要求过 Logs、Zone 与 Workers Scripts 读权限，没有任何代码路径会用到它们。（这个最小集是从代码的调用点推导出来的；自己快速验证的办法：建一枚只有 Zone → Analytics: Read 的令牌，跑一次 `flarehound -once -dry-run`。）审计会用同一主机上的 REST API 额外读取规则集。你的令牌永远不会离开你的机器，也不会被程序写进磁盘或日志。

## Web 控制台

```bash
# config.json: "console": {"enabled": true}
flarehound -config config.json console init-admin --user you   # or use the one-time setup link it logs
flarehound -config config.json console                         # http://127.0.0.1:8640
```

与看守是两个进程，读同一份归档：最新一小时对照 28 天基线、按 User-Agent / ASN / 未缓存路径排的涨幅与跌幅榜、新面孔、带告警与封锁时间线的历史、WAF 审计与封锁列表。手机优先设计。账号（管理员 / 查看者）带 TOTP；默认只绑回环地址——通过 Tailscale、TLS 反向代理或 Cloudflare Tunnel 访问它。

把写令牌给控制台进程（永远不给看守），管理员就能在里面封锁：从涨跌榜预填、与 CLI 相同的护栏与审阅、每次变更要一个新的两步验证码、动手前先按账号记审计、读回验证、一键撤销、自动的封前/封后对比。任何视图都可以冻结成只读快照，带会过期、可吊销的分享链接。用户也可以把 Google 或 GitHub 账号绑定到本地账号后用它们登录。见 [docs/console.md](docs/console.md)。

有多个 zone 时，首页把它们全列出来，按「哪个最需要关注」排序。设置也在控制台里——通知渠道带测试发送（由看守用它自己的环境发送）、告警线在生效前先拿最近 7 天回放预览、已知面孔、按 ASN 的网络命名——控制台界面可选英文或中文。配置了邮件（SMTP 或 Resend）与公开 base URL 后，忘记密码可以邮件重置。

## 一键封锁

告警会点名元凶，并打印封它的命令：

```bash
flarehound block asn 207990 --action block --for 24h
flarehound block ip 45.13.7.9
flarehound block country XX --action challenge
flarehound block ua "BadBot/1.0" --for 7d --reason "scraper, 11-17 incident"
flarehound unblock asn 207990
flarehound blocks            # everything blocked, with 7-day attempts and expiry
flarehound enforce           # 可选：没有控制台时负责解除到期封锁
```

任何变更之前，你先看到确切的方案——它要改的那条规则与改后的表达式、自定义规则配额、目标在最近一小时超额流量里实测的占比、以及全部警告——然后确认一次。FlareHound 只动它自己的对象（名为 `flarehound-…` 的规则、IP 名单 `flarehound_block`），每种目标类型合并进一条规则，几乎不占你的配额；在 ASN 与国家规则上始终放行已验证的搜索机器人；改完读回验证。它拒绝封 Cloudflare 的地址段、你的源站 IP（来自 DNS）、私有地址段，以及 `blocking.never_block` 名单里的一切。封住宅/骨干 ASN 或整个国家，需要重新输入一遍 ASN 或国家代码确认。每个动作都写进只追加的审计日志，日报会列出每条封锁的尝试次数——尝试停了就解除封锁，而不是等它安静下来。

持有写令牌的控制台会自行解除到期封锁（每 5 分钟一轮）；没有控制台时运行 `flarehound enforce`——在 Docker 里 `docker compose --profile admin up -d` 会带着写令牌启动它，`docker compose run --rm flarehound-admin block …` 用来跑命令。

## WAF 基础与配方

不熟悉 WAF 规则？[WAF 基础](docs/waf-guide.md)（[中文](docs/waf-guide-zh.md)）讲顺序、已验证机器人、封锁与挑战的区别、以及窄豁免；配方则直接替你做：

```bash
flarehound rules recipes
flarehound rules recipe protect-paths --path '/login*, /admin*'
flarehound audit          # ends with "How to fix"
```

每条规则都有大白话解释（`flarehound rules list`、控制台的 WAF 规则页），每次变更都完整展示、经确认、先备份、再读回。

## 应用规则变更

属于规则变更的建议会自带应用它的命令，你也可以直接管理自定义规则、限速规则与缓存规则：

```bash
flarehound rules list [--phase custom|ratelimit|cache]
flarehound rules add --action managed_challenge --expr 'starts_with(http.request.uri.path, "/login")' --desc "challenge login" [--before 1]
flarehound rules edit 3 --enabled false
flarehound rules move 3 --before 1        # or --last
flarehound rules delete 3
flarehound ratelimit add --path '/rank' --requests 20 --period 10
flarehound cache add --path '/assets/*' --ttl 1d
flarehound rules backups                   # snapshots taken before each change
flarehound rules restore 12                # put a phase back as it was
flarehound rules log                       # who changed what, verified or not
```

每次变更都完整展示（编辑时逐字段旧 → 新），由你确认——刻意没有 `--yes`——先备份（进归档，并写 `data/backups/<zone>/*.json`），读回后逐字段、逐位置比对，再记进审计日志。表达式在发送前先做本地语法检查；配额按套餐核对；封锁模块自有的规则不许动。缓存规则还额外需要写令牌上有 **Zone → Cache Rules: Edit**。

## WAF 规则审计

`flarehound audit`（以及每份日报中的一节）以审阅者的眼光只读检查你的自定义规则：

- **覆盖缺口**：每个敏感路径（`path_rules`、`daily.paths`、`waf_audit.sensitive_paths`，或 zone 自己的 `zones[].waf_audit.sensitive_paths`）是否被封锁/挑战规则覆盖？完全覆盖、仅有条件覆盖（如只针对某个 User-Agent）、完全没覆盖——还是被排在它前面的 skip 规则豁免掉了。
- **顺序问题**：永远不会命中的规则（前面的 Block 规则已匹配了它们能匹配的一切）、完全重复的规则、以及被前面的 skip 规则放行的防护。
- **豁免口子**：条件只用了任何客户端都能伪造的字段（User-Agent、Referer、路径……）的 skip 规则——「任何人把 UA 写成 `MyMonitor` 就能跳过你的 WAF」。
- **命中与僵尸**（有防火墙事件的套餐）：每条规则 7 天与 30 天命中数；30 天零命中的规则会被报告（不会被删——安静不等于没用）。
- **配额**：接近套餐自定义规则上限时，哪些规则可以合并。

它自带一个 Cloudflare 规则语言的解析器，用三值逻辑对探测请求求值，所以只声称它能证明的东西。规则集版本一变，下一轮小时检查会重新审计并报告问题。

## 校准：为什么 FlareHound 的数字和仪表盘不一样

FlareHound 读的是 Cloudflare 的 *adaptive*（自适应）分析数据：它是采样的，还会把 Worker 子请求与缓存操作计入；仪表盘不计。在一个真实 zone 上，FlareHound 的请求数大约是仪表盘的 ≈ 1.29 倍。所有阈值都以 FlareHound 的口径为准。`flarehound calibrate --days 7` 显示逐日比率（请求、缓存命中、边缘 5xx、采样率），以及 `min_count` 换算成仪表盘口径是多少；每份日报都带一行比率。

## 它如何决策

默认告警线（全部可配置——这些是本工具所基于的那次事件里实战验证过的值）：

| 信号 | 默认 |
|---|---|
| Worker 调用量 vs. 昨天 | +35% |
| Zone 请求数 vs. 昨天 | +35% |
| Worker CPU P50 vs. 昨天 | +25% |
| Dynamic（未缓存）响应 vs. 昨天 | +50% |
| 源站 5xx | 3× 基线 **且** > 50 |
| 源站不可达（边缘 52x） | 每小时 ≥ 10（健康源站应为 0） |
| 源站延迟 P95（首字节） | +100% **且** ≥ 1 秒 |
| Top 10 内的新面孔（UA 或 ASN） | > 5,000 请求/小时 |
| 请求或调用量塌陷 | −50%（3 分钟后复读；数据还在路上时绝不判塌陷） |
| 百分比规则的量底线 | 每窗口 1,000 请求 |

按路径的覆盖（`path_rules`）会给 `/login*` 这类低量敏感路径设更紧的线。

开箱处理的一类已知误报：正牌爬虫（Googlebot、Bingbot、Applebot、YandexBot、Baiduspider）升级 User-Agent 版本号会触发「新面孔」——FlareHound 会先核对该 UA 的流量是否 ≥ 90% 来自爬虫自己的 ASN，再决定豁免，所以冒牌货照样报警。把你自己的监控与服务登记进 `known_faces`。

**告警纪律：** 异常开始时报一次；只有出现*新*信号、或已报信号再涨 25% 时才再报；连续两轮干净后发一行恢复。投递失败重试 3 次，然后在磁盘上排队等下一轮。

**日报**（默认本地时间 08:00）：最近 24 小时对照前 24 小时、缓存成本拆分、Top 路径 / ASN / User-Agent（新的会标记）、每条规则的防火墙事件，以及你的固定检查点（`daily.paths` 的回源上限、`daily.artifacts` 已知记账条目）。

## 部署

主要形态是一个 Go 单二进制打进 Docker 容器，跑在**你自己的** VPS、家用服务器或 NAS 上——刻意*不*跑在 Cloudflare 上，这样被看守的平台自己出事时，看守没有盲区。引擎只需要出站 HTTPS 和一个本地状态文件；基于 Cloudflare Workers（Cron Triggers）的部署适配在路线图上，作为备选形态。

## 路线图

- ~~v0.2~~ — 日报（24 小时对比 + 固定检查点）✅
- ~~v0.3~~ — 完整日内看守（新面孔检测、升级/恢复状态机、归因查询）✅
- ~~v0.4~~ — 建议引擎（封锁 / 挑战 / 限速 / 缓存候选）+ 本地 SQLite 归档 ✅
- ~~v0.5~~ — 一键封锁（IP / CIDR / ASN / 国家 / User-Agent——从告警或 CLI 封、带过期的封锁、护栏、审计日志）✅
- ~~v0.6~~ — WAF 规则审计（敏感路径覆盖缺口、顺序/冗余问题、逐规则命中统计、过宽豁免）✅
- ~~v0.7~~ — 通用动作模块（用独立写令牌执行已批准的建议、变更前备份、读回验证）✅
- ~~v0.8~~ — 更多通知渠道（Slack、Discord、企业微信、飞书、邮件）、多 zone 并行检查 ✅
- ~~v1.0~~ — 对照仪表盘校准（`flarehound calibrate`）、文档站、首个稳定版 ✅

- ~~v1.3~~ — 只读 Web 控制台（对照基线的概览、涨跌榜、新面孔、历史、WAF 审计、封锁）+ 内置账号与两步登录 ✅
- ~~v1.4~~ — 控制台内封锁（写令牌只进控制台进程、护栏确认、封前/封后效果、撤销、只读快照）✅
- ~~v1.5~~ — Google / GitHub 登录绑定本地账号 ✅
- ~~v1.7~~ — WAF 基础与规则配方、大白话规则说明；实时小时与涨跌榜下钻；扫码设置 TOTP 与邮件重置密码 ✅
- ~~v1.8~~ — 控制台语言切换（英文 / 中文）✅
- ~~v1.9~~ — 控制台内设置（通知带测试发送、告警线带回放预览、已知面孔）与网络命名 ✅
- ~~v1.10~~ — 跨 zone 首页、封锁裁决、被规则覆盖的面孔标记、WAF 审计与规则快照 ✅
- ~~v1.11~~ — 按 zone 的 WAF 审计覆盖（每个 zone 自己的主机与敏感路径）✅
- ~~v1.12~~ — 出站 SMTP 被封时改走 HTTPS 发邮件（Resend）✅


## 局限

- Cloudflare 的 GraphQL Analytics 是采样的，且没有 Referer 维度；超大站点会觉得归因太粗。FlareHound 面向中小站点。
- 分析能暴露什么取决于套餐。FlareHound 启动时逐个 zone 探测能力，缺了就降级而不是失败：在 **Free** 上，没有 ASN 拆分（新 ASN 检测与 ASN 建议关闭），也没有防火墙事件（封锁尝试次数显示 "n/a"）；爬虫改用 Cloudflare 自家的 `verifiedBotCategory` 核验。
- 分析入库延迟（约 5–10 分钟）决定了检测下限。这是看守，不是实时盾牌——边缘规则才是盾牌。
- 本地归档存的是小时聚合，不是原始请求日志；它还原不了单个请求，历史也从你部署那天起才开始积累。
- 检测路径里没有 AI：所有发现都是确定性的、可用同一份数据复现。一个可选的、自带密钥的 AI 解释者（只负责讲述发现）在长期路线图上——它永远不会拦截、压制或处置任何告警。

## 许可证

MIT © 2026 playwjj
