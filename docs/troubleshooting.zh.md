# 排错 {#troubleshooting}

先运行 **`flarehound doctor`**：它一次性检查配置、每个 Token 能访问什么（并点名缺失的权限）、套餐能力、心跳和归档。

FlareHound 的日志输出到 stderr；在 Docker 中使用 `docker compose logs -f flarehound`。所有日志输出中的密钥都会被脱敏。如果容器显示 `unhealthy`，说明看守循环的心跳已过期——请查看日志。

## 启动错误 {#startup-errors}

| 消息（节选） | 解决方法 |
|---|---|
| `environment variable CF_API_TOKEN is empty` | 导出只读 Token，并把它传给容器。 |
| `zones[0].zone_id … is not a 32-char hex Cloudflare zone ID` | 从该 zone 的 Overview 页面复制 zone ID。 |
| `account_id … (required to watch Workers)` | 设置 `cloudflare.account_id`，或移除 `workers`。 |
| `schedule.intraday_interval must be a whole number of hours` | 使用 `1h`、`2h`、… |
| `schedule.intraday_offset must be within [0, 1h)` | 例如 `7m`。 |
| `schedule.daily_report_at … must be HH:MM` | 例如 `"08:00"`，或设为 `""` 关闭。 |
| `notify.slack_webhook_url_env names X, but that environment variable is empty` | 设置该变量（在容器内），或移除这个键。Discord、企业微信、飞书同理。 |
| `notify.email needs smtp_host, from and at least one to` | 补全 `email` 配置块。 |
| `notify.email.password_env must name a non-empty environment variable when username is set` | 设置密码变量。 |
| `notify.email.api_key_env must name a non-empty environment variable for provider resend` | 设置 Resend API key 变量。 |
| `blocking.write_token_env must differ from cloudflare.api_token_env` | 把两个 Token 放在不同的变量里。 |
| `archive.hourly_retention_days must be >= 30` | 长基线需要 28 天。 |
| `warning: no notification channel configured` | 不是错误：发现只会写入日志。请配置一个 [通知渠道](channels.md)。 |

## 访问权限与套餐 {#access-and-plan}

- **`the token cannot see this zone/account`**——Token 的作用范围不包含该 zone，或者（配置了 `workers` 时）缺少该账户的 Account → Account Analytics: Read。
- **`not available on this plan, degraded: clientAsn, clientASNDescription, firewall events`**——在 Free 上属于正常现象。见 [限制](limitations.md#plans)。
- **`capability probe failed, assuming full analytics`**——探测查询失败；FlareHound 继续运行，并在下一轮重试。如果后续查询因字段缺失而失败，请检查 Token 和套餐。
- **WAF 体检显示「unavailable … lacks Zone → WAF: Read」**——给只读 Token 加上 WAF: Read，或设置 `waf_audit.disabled`。

## 没有消息 {#no-messages}

- **默认就是安静的。** 没有异常就没有消息——只有日报每天都发。在日志中查找 `quiet (findings=0, active=false)`。
- **`window … already evaluated, skipping`**——每个窗口只评估一次；重启或之前的一次 `-once` 运行已经评估过了。`-dry-run` 运行不算：它们只打印不发送，也不留下任何痕迹（不写状态文件、不记告警历史），因此随后的正式运行仍会评估该窗口。
- **投递失败**——发送失败的消息会排入 `data/outbox.json`，下一轮带 `[delayed]` 重发；超过 48 小时的消息会被丢弃并记一行日志。请查看日志中记录的错误（`HTTP 4xx`、`wecom errcode …`、`feishu code …`、`email: …`）。
- **Telegram** 只有在 Token 变量和 `telegram_chat_id` 都设置了时才会发送；webhook 或 Telegram 的变量为空时，该渠道会被静默关闭。
- **邮件**——`server does not offer STARTTLS`：改用 `"tls": "tls"`（端口 465），或仅在本地中继时使用 `"none"`。使用 `none` 时绝不会发送凭据。`connect: … i/o timeout` 通常意味着主机屏蔽了出站 SMTP——改用 `"provider": "resend"`（HTTPS）。

## 数字看起来不对 {#numbers-look-wrong}

- **比面板高**——符合预期；运行 `flarehound calibrate`。见 [口径校准](archive.md#calibration)。
- **边缘有大量 504 / 5xx，但访客一切正常**——很可能是缓存操作造成的记账假象；把它们列在 [`daily.artifacts`](configuration.md#daily) 下。
- **骤降显示「withheld: window still filling」（数据未落定、暂不报）**——`settle_delay` 之后的重读计数仍在增长；数据还没有落定。如果经常出现，请调大 `schedule.intraday_offset`。
- **小站点告警太多**——调高 `thresholds.min_count`；把你自己的监控登记在 `known_faces` 下。

## 封锁与规则变更 {#blocking-and-rule-changes}

- **`environment variable CF_WRITE_TOKEN is empty`**——封锁和规则命令需要单独的写 Token。在 Docker 中，请使用 `flarehound-admin` 服务。
- **`cannot read DNS records to protect your origin IPs`**——给写 Token 授予 Zone → DNS: Read，或在确定无误时传入 `--skip-origin-check`。
- **`custom-rule quota is full`**——解封过时的条目、合并规则（见 [体检的额度一节](audit.md#quota)），或授予 Zone → WAF: Edit，以便 IP 和 ASN 可以改用 IP Access Rules 兜底。
- **`--for needs the archive`** / **`the execution module needs the archive`**——把 `archive.disabled` 设为 false。
- **`rule changes have no --yes`**——这是有意设计的；请交互式确认。
- **到期的封锁没有被解除**——控制台必须持有写 Token（它每 5 分钟解除一次到期封锁），或者 `flarehound enforce` 必须在运行（`docker compose --profile admin up -d`）。两者都不满足时，封锁页面会给出警告。
- 规则变更后**回读不一致**——错误信息中包含 `flarehound rules restore <id>`；请先与面板核对。
