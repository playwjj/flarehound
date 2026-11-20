# 配置参考 {#configuration-reference}

FlareHound 读取一个 JSON 文件（`-config`，默认 `config.json`）。除标明必填的以外，每个配置项都是可选的；未写出的配置项保持默认值——缺失的阈值永远不会被当作 0。密钥从不保存在文件中：`*_env` 配置项写的是保存该值的环境变量名。

完整示例见仓库中的 `config.example.json`。校验错误会让进程在启动时停止，并给出出错配置项的名称。

## cloudflare {#cloudflare}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `cloudflare.account_id` | string | `""` | 32 位十六进制账户 ID。任何 zone 配置了 `workers` 时必填。封锁也用它来使用账户级 IP 列表（没有它时，IP 封锁改用表达式规则）。 |
| `cloudflare.api_token_env` | string | `"CF_API_TOKEN"` | 保存**只读** Token 的环境变量。为空时启动失败。 |
| `cloudflare.zones` | array | — | **必填**，至少一个 zone。 |
| `cloudflare.zones[].zone_id` | string | — | **必填。** 32 位十六进制 zone ID。 |
| `cloudflare.zones[].name` | string | zone ID | 显示名称；同时也是 WAF 规则体检的默认探测 host，以及 `--zone` 的选择器。 |
| `cloudflare.zones[].workers` | string[] | `[]` | 要看守的 Worker 脚本名（调用量与 CPU P50 / P99）。每个单独评估。需要 Account Analytics: Read。 |
| `cloudflare.zones[].waf_audit.hosts` | string[] | 属于本 zone 的全局 host，否则为 zone 名称 | 本 zone 的 WAF 规则体检探测 host。每个都必须是该 zone 本身或其子域名。 |
| `cloudflare.zones[].waf_audit.sensitive_paths` | string[] | — | 本 zone 用于覆盖检查的完整敏感路径列表。一旦设置（即使是 `[]`），本 zone 就不再使用默认列表。 |

## schedule {#schedule}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `schedule.intraday_interval` | duration | `"1h"` | 看守间隔与窗口长度。必须是整数小时（窗口是完整的整点小时）。 |
| `schedule.intraday_offset` | duration | `"7m"` | 整点过后多久运行检查，用于吸收分析数据的入库延迟。必须在 `[0, 1h)` 之内。 |
| `schedule.settle_delay` | duration | `"3m"` | 窗口看起来像骤降时，等待多久再重读一次，以区分入库延迟和真实下跌。 |
| `schedule.daily_report_at` | `"HH:MM"` | `"08:00"` | 日报的本地时间。空字符串表示关闭日报。 |
| `schedule.timezone` | string | 主机本地时间 | IANA 时区名，例如 `"Asia/Shanghai"`。镜像内置了时区数据库。 |
| `schedule.max_parallel_zones` | int | `4` | 同时检查多少个 zone。允许 1–16。 |

时长使用 Go 语法（`90s`、`7m`、`2h`）。

## thresholds {#thresholds}

检测阈值；各项如何应用见 [检测](detection.md)。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `thresholds.total_up_pct` | number | `35` | zone 请求量相对基线的涨幅（%）。 |
| `thresholds.worker_calls_up_pct` | number | `35` | Worker 调用量涨幅（%）。 |
| `thresholds.cpu_p50_up_pct` | number | `25` | Worker CPU P50 涨幅（%）。 |
| `thresholds.dynamic_up_pct` | number | `50` | 未缓存（`dynamic`）响应涨幅（%）。 |
| `thresholds.origin_5xx_multiplier` | number | `3` | 源站 5xx 必须达到基线的这个倍数…… |
| `thresholds.origin_5xx_min` | int | `50` | ……并且超过这个绝对数量。 |
| `thresholds.new_face_min_count` | int | `5000` | 进入 Top 10 的新 UA / ASN 在窗口内的请求数必须超过此值。 |
| `thresholds.collapse_down_pct` | number | `50` | 请求量或调用量的降幅（%）。 |
| `thresholds.min_count` | int | `1000` | 百分比规则的量级下限：当前窗口（上涨）或基线（下跌）必须达到此值；CPU P50 要求两个窗口的调用量都 ≥ 此值。 |
| `thresholds.escalation_pct` | number | `25` | 已报过的信号，只有在其已报峰值基础上再增长此百分比才会再次告警。 |
| `thresholds.recovery_clean_rounds` | int | `2` | 连续多少轮无命中后发送「恢复」消息。 |
| `thresholds.origin_slow_up_pct` | number | `100` | 源站延迟 P95（首字节，否则为完整响应）相对基线的涨幅（%）…… |
| `thresholds.origin_slow_min_ms` | number | `1000` | ……并且当前 P95 至少达到这么多毫秒（40 → 80 ms 不算新闻）。 |
| `thresholds.unreachable_min` | int | `10` | 每个窗口的边缘 52x（源站不可达）达到多少才告警。 |
| `thresholds.baseline_min_samples` | int | `3` | 新指标的归档基线需要多少个已测得的同时段天数，其阈值（`origin_unreachable`、`origin_slow`、CPU P99 检查）才可能触发——见 [基线成熟度](detection.md#new-metrics-baseline-maturity)。`0` 关闭此门槛。 |

## path_rules {#path_rules}

针对敏感、低流量路径的路径级阈值——这些路径的异常会被 zone 总量淹没。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `path_rules[].name` | string | 路径本身 | 告警中的信号名称。 |
| `path_rules[].path` | string | — | **必填。** 必须以 `/` 开头；`*` 为通配符（`/login*`）。 |
| `path_rules[].up_pct` | number | `100` | 相对基线的涨幅（%）。 |
| `path_rules[].min_count` | int | `20` | 当前窗口的量级下限。 |
| `path_rules[].dynamic_only` | bool | `false` | 只统计未缓存（`dynamic`）请求——即该路径真实的渲染负载。 |

路径规则同时也是建议和 [WAF 规则体检](audit.md) 所用的敏感路径。每条规则每个窗口增加一次查询。

## daily {#daily}

[日报](reports.md#daily-report) 的固定检查点。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `daily.paths[].label` | string | 路径本身 | 检查点名称。 |
| `daily.paths[].path` | string | — | **必填。** 必须以 `/` 开头；`*` 为通配符。同时也是敏感路径。 |
| `daily.paths[].max` | int | `0` | 24 小时内到达源站的最大请求数（未由边缘缓存提供的请求）；超过时该行标记 ⚠。 |
| `daily.artifacts[].label` | string | `""` | 一个已知记账假象的名称。 |
| `daily.artifacts[].path` | string | `""` | 路径模式（`*` 通配符）。 |
| `daily.artifacts[].edge_status` | int | `0` | 要统计的边缘状态码（例如 `504`）；`0` 统计所有状态码。 |

## known_faces {#known_faces}

永远不算作新面孔的来源。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `known_faces.asns` | int[] | `[]` | ASN（你的监控、合作方、你自己的服务）。 |
| `known_faces.user_agents` | string[] | `[]` | 不区分大小写的 UA 子串。 |

## rule_names {#rule_names}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `rule_names` | object | `{}` | 防火墙规则 ID → 报告中显示名称的映射。有 WAF: Read 时，名称会自动取自规则描述；此映射会覆盖它们。 |

## report {#report}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `report.language` | string | `"en"` | `"en"` 或 `"zh"`（中文）：报告和通知的语言，也是控制台的默认语言（每个人都可以用控制台的 EN / 中文 按钮切换）。 |

`report.visuals`（bool，默认 `true`）：附带图表，并以 HTML 发送邮件——见 [图表与 HTML](channels.md#charts-and-html-reportvisuals-default-on)。

## notify {#notify}

所有渠道都是可选的，并且可以组合使用；一个都不配置时，发现只出现在日志中。各渠道详情：[通知渠道](channels.md)。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `notify.webhook_url_env` | string | `""` | 保存通用 webhook URL 的变量。优先于 `webhook_url`。 |
| `notify.webhook_url` | string | `""` | 明文 webhook URL，为兼容而保留。建议使用 `webhook_url_env`。 |
| `notify.telegram_bot_token_env` | string | `""` | 保存 Telegram bot token 的变量。 |
| `notify.telegram_chat_id` | string | `""` | Telegram chat ID。两者都设置时 Telegram 才启用。 |
| `notify.jsonl_file` | string | `""` | 把每条消息以一行 JSON 追加到此文件（权限 0644）。每轮还会写入一条 `heartbeat` 记录。达到 32 MB 时轮转，保留 3 个轮转副本；保存在其旁边的图表在 90 天后删除（[详情](channels.md#jsonl-file)）。 |
| `notify.heartbeat_url_env` | string | `""` | 保存 healthchecks.io 风格 URL 的变量，每轮结束后 ping 一次（有 zone 出错时 ping `/fail`）。指定了变量但其为空时启动失败。见 [心跳](channels.md#heartbeat-dead-man-switch)。 |
| `notify.slack_webhook_url_env` | string | `""` | 保存 Slack incoming webhook URL 的变量。 |
| `notify.discord_webhook_url_env` | string | `""` | 保存 Discord webhook URL 的变量。 |
| `notify.wecom_webhook_url_env` | string | `""` | 保存企业微信群机器人 URL 的变量。 |
| `notify.feishu_webhook_url_env` | string | `""` | 保存飞书 / Lark 自定义机器人 URL 的变量。 |
| `notify.feishu_secret_env` | string | `""` | 保存飞书签名密钥的变量（可选）。 |
| `notify.email` | object | 不设置 | 邮件渠道（SMTP 或 Resend 的 HTTP API）；见下文。 |

对于 Slack、Discord、企业微信和飞书，指定了变量但其为空属于启动错误。

`notify.email`：

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `provider` | string | `"smtp"` | `smtp`，或 `resend`：通过 [Resend](https://resend.com) 以 HTTPS 发送（适用于出站 SMTP 端口被封的主机）。 |
| `api_key_env` | string | `""` | 仅 `resend` 使用，且在该模式下**必填**：保存 Resend API key 的变量。 |
| `smtp_host` | string | — | `smtp` 模式**必填**；`resend` 不使用（`smtp_port`、`tls`、`username`、`password_env` 同样不使用）。 |
| `smtp_port` | int | 按 `tls`：587 / 465 / 25 | SMTP 端口。 |
| `tls` | string | `"starttls"` | `starttls`、`tls`（隐式 TLS）或 `none`（仅限本地中继）。 |
| `username` | string | `""` | SMTP 用户名；设置后 `password_env` 必须指向一个非空变量。 |
| `password_env` | string | `""` | 保存 SMTP 密码的变量。 |
| `from` | string | — | **必填。** 发件地址。 |
| `to` | string[] | — | **必填**，至少一个收件人。 |

## state_file {#state_file}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `state_file` | string | `"data/state.json"` | 告警状态机文件。配置了多个 zone 时，每个 zone 会获得一个由它派生的独立文件（`data/state-example-com.json`）。它所在的目录就是**数据目录**：通知发件箱（`outbox.json`）、规则备份（`backups/`）和默认的归档都保存在这里。相对路径相对于工作目录（镜像中为 `/app`）。 |

## blocking {#blocking}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `blocking.write_token_env` | string | `"CF_WRITE_TOKEN"` | 保存独立写 Token 的变量。必须与 `cloudflare.api_token_env` 不同。只由封锁与规则变更命令读取。 |
| `blocking.never_block` | string[] | `[]` | 永远不会被封锁、也不会作为封锁候选出现的 IP / CIDR。每一项都必须能解析为 IP 或 CIDR。 |
| `blocking.never_block_asns` | int[] | `[]` | 永远不封锁、也不建议封锁的 ASN。 |

## waf_audit {#waf_audit}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `waf_audit.disabled` | bool | `false` | 关闭 WAF 规则体检（日报中的体检段落、规则变化时的重新体检、`flarehound audit`）。 |
| `waf_audit.hosts` | string[] | zone 名称 | 要探测的 host；规则经常限定 `http.host`，因此覆盖情况按 host 判断。 |
| `waf_audit.sensitive_paths` | string[] | `[]` | 额外的敏感路径模式，在 `path_rules` 和 `daily.paths` 之外补充。 |

配置了多个 zone 时，每个 zone 只探测属于自己的 `waf_audit.hosts`（该 zone 本身或其子域名）。默认的敏感路径列表（`path_rules` + `daily.paths` + `waf_audit.sensitive_paths`）只适用于这些 host 所属的 zone——如果没有全局 host，则只适用于第一个 zone。请为其他每个 zone 配置各自的列表；在此之前，它们的体检会显示覆盖情况**未配置**，而不是拿另一个站点的路径来打分：

```json
"zones": [
  { "name": "example.com", "zone_id": "…" },
  { "name": "blog.example.org", "zone_id": "…",
    "waf_audit": { "sensitive_paths": ["/wp-login.php", "/wp-admin*", "/xmlrpc.php"] } }
]
```

## archive {#archive}

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `archive.disabled` | bool | `false` | 关闭本地 SQLite 归档。`-backfill`、`block --for` 和规则变更命令都需要归档。 |
| `archive.file` | string | `<data dir>/archive.db` | 归档路径。 |
| `archive.hourly_retention_days` | int | `400` | 小时快照（约 13 个月）、已归档告警以及此后未再出现的新面孔的保留天数。最小 30。每日快照、封锁日志和规则备份 / 变更永久保留。见 [磁盘空间](archive.md#disk-space)。 |

## geoip {#geoip}

**IP 归属地**（v1.17）：FlareHound 显示的每个 IP——IP 榜、下钻、封锁审核、封锁列表、告警、日报和 `flarehound blocks`——后面都会跟上它注册或路由所在的国家，数据读自本地的 MMDB 国家库。仅用于显示：国家从不参与检测、告警、严重程度或封锁计划，而且是在显示时才查询，从不归档（更新的库可能会把某个地址归到别处）。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `geoip.country_db` | string | — | 国家库（MMDB）的路径。为空时：先找 `<data dir>/country.mmdb`，再用 Docker 镜像自带的库（`/usr/share/flarehound/country.mmdb`）。 |

- **库。** 默认使用 DB-IP 的免费 [IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)（每月更新，CC BY 4.0 — IP geolocation by DB-IP）；Docker 镜像打包的是其构建当月的版本。MaxMind 的 GeoLite2-Country 也可以使用，但其许可不允许 FlareHound 随附分发：请自行下载，并把 `geoip.country_db` 指向它。IPv4 和 IPv6 都覆盖。
- **更新。** `flarehound geoip update` 下载最新的 DB-IP lite 文件，检查它能否作为国家库读取，然后原子替换 `geoip.country_db`（或 `<data dir>/country.mmdb`，其优先级高于镜像自带的副本）。它不需要任何 Token。运行中的进程会在 10 分钟内载入新文件。国家归属变化很慢：几个月前的库也完全够用，没有任何东西强制你更新。
- **库缺失或损坏：** 该功能静默关闭——每个 IP 都和以前一样显示，其他一切不变。`flarehound doctor` 会说明加载了哪个库（类型、构建日期、文件日期、网段数）、没有找到库，或者某个文件为何无法使用。
- **它意味着什么。** *IP 归属地* 是该地址注册或路由所在的地方，而不是其运营者所在的地方：住宅代理的出口国家并不能说明是谁在操控它，数据中心地址显示的就是数据中心所在地。它只是网络（ASN）和流量之外一条廉价的上下文信息，而不是定论。

## console {#console}

Web 控制台（v1.3，只读）——见 [Web 控制台](console.md)。

| 配置项 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `console.enabled` | bool | `false` | 除非设为 true，否则 `flarehound console` 拒绝启动。 |
| `console.listen` | string | `127.0.0.1:8640` | 监听地址。请保持在回环地址上，通过 Tailscale、TLS 反向代理或 Cloudflare Tunnel 访问：FlareHound 本身不做 TLS。 |
| `console.db_file` | string | `<data dir>/console.db` | 账号与会话（文件权限 0600）。看守进程从不打开它。 |
| `console.base_url` | string | — | 人们访问控制台所用的地址，例如 `https://hound.example.ts.net`。设置后，通知会附带指向对应视图的深层链接，邀请、密码重置和登录回调链接也会使用它。与 `notify.email` 一起配置时，会启用邮件重置密码。 |
| `console.refresh_seconds` | int | `300` | 实时视图的自动刷新间隔。最小 30。 |
| `console.session_hours` | int | `12` | 登录会话的空闲有效期（1–720）。 |
| `console.snapshots` | string | `admins` | 谁可以创建只读快照（无需登录即可访问的分享链接）：`admins`、`everyone` 或 `off`。 |
| `console.require_totp` | bool | `false` | 每个账号在使用控制台前都必须设置二次验证。 |
| `console.trusted_proxies` | list | `[]` | 控制台前方反向代理的 IP / CIDR。只有这些代理可以设置 `X-Forwarded-For`、`X-Forwarded-Proto` 或代理身份头。 |
| `console.proxy_auth.header` | string | — | 信任由认证代理注入的身份头（例如 `Cf-Access-Authenticated-User-Email`）。需要 `trusted_proxies`。 |
| `console.proxy_auth.default_role` | string | `viewer` | 不匹配任何本地账号的代理身份所获得的角色：`viewer` 或 `none`（拒绝）。 |
| `console.proxy_auth.disable_login` | bool | `false` | 关闭内置的密码登录（只接受代理身份）。 |
| `console.oauth.google` | object | — | Google 登录：`{"client_id": "…", "client_secret_env": "GOOGLE_OAUTH_SECRET"}`。需要 `base_url`。见 [第三方登录](console.md#sign-in-with-google-or-github)。 |
| `console.oauth.github` | object | — | GitHub 登录：`{"client_id": "…", "client_secret_env": "GITHUB_OAUTH_SECRET"}`。需要 `base_url`。 |

## asn_names {#asn_names}

网络的简称，在通知和控制台中替代注册名称使用（网络类型仍按注册名称判断）：

```json
"asn_names": { "45102": "aliyun", "4837": "联通骨干", "207990": "HostRoyale" }
```

也可以在控制台中设置名称（设置 → ASN 名称，或任意 ASN 旁边的*命名*）。

## 在控制台中修改的设置 {#settings-changed-in-the-console}

通知（渠道开关、非密钥参数、变量名）、`thresholds`、`known_faces` 的新增项以及 `asn_names` 都可以在控制台中修改。这些修改保存在数据目录下的 `settings.json` 中，每次加载时叠加在本文件之上；看守在每轮开始前重新读取它们。本文件从不会被修改。见 [Web 控制台 → 设置](console.md#settings)。

## 环境变量一览 {#environment-variables-at-a-glance}

| 变量（默认名） | 由哪个配置项设置 | 使用者 |
|---|---|---|
| `CF_API_TOKEN` | `cloudflare.api_token_env` | 看守与所有命令 |
| `CF_WRITE_TOKEN` | `blocking.write_token_env` | `block`、`unblock`、`blocks`、`enforce`、`rules`、`ratelimit`、`cache` |
| *（你自己的变量名）* | `notify.*_env`、`notify.email.password_env` / `api_key_env` | 通知渠道；心跳 ping 使用 `notify.heartbeat_url_env` |
