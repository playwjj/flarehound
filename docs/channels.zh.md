# 通知渠道 {#notification-channels}

在 `notify` 下可以配置任意数量的渠道；每条消息都会发往所有渠道。没有配置任何渠道时，FlareHound 会记录一条警告，发现的问题只出现在它的日志里。

## 投递保证（所有渠道） {#delivery-guarantees-all-channels}

- 每次发送最多尝试 **3 次**，指数退避（2 秒，然后 4 秒）。
- 仍然失败的消息会**按渠道**暂存在数据目录下的 `outbox.json`（发件箱）中，在下一轮开始时重新发送，并加上 `[delayed]` 前缀。
- 排队超过 **48 小时**的消息会被丢弃并记一行日志——两天前的告警只是噪音。
- HTTP 渠道 30 秒超时；非 2xx 状态视为失败。
- 错误消息中从不包含端点 URL（机器人 URL 里嵌有密钥）。所有渠道的密钥都会从日志中脱敏。
- 会拆分长消息的渠道给各部分编号 `(i/n)`；拆分点优先选在换行处，过长的单行则在字符边界处截断（绝不切在多字节字符中间）。

| 渠道 | 长度处理 |
|---|---|
| Webhook、JSONL 文件、邮件 | 整条消息 |
| Telegram | 按 4,096 个字符拆分 |
| Slack | 按 39,000 个字符拆分 |
| Discord | 按 2,000 个字符拆分 |
| 企业微信 | 按 2,048 字节拆分 |
| 飞书 / Lark | 按 4,000 个字符拆分 |

`-dry-run` 会把所有渠道替换为标准输出（stdout）。

## 通用 Webhook {#generic-webhook}

```json
"notify": { "webhook_url_env": "FLAREHOUND_WEBHOOK_URL" }
```

| 键 | 含义 |
|---|---|
| `webhook_url_env` | 存放 URL 的环境变量（推荐）。设置后优先于 `webhook_url`。 |
| `webhook_url` | 直接写在配置文件里的 URL，为兼容而保留。 |

FlareHound 以 `Content-Type: application/json` 发送 POST：

```json
{
  "kind": "intraday",
  "zone": "example.com",
  "decision": "alert",
  "window_from": "2026-11-17T00:00:00Z",
  "window_to": "2026-11-17T01:00:00Z",
  "rules": ["dynamic_up", "worker_calls_up:web"],
  "text": "FlareHound · example.com — anomaly\n…"
}
```

`text` 是主字段，因此只读取 `text` 的接收端可以照常工作。`decision` 和 `rules` 为空时省略；从发件箱重发的消息会加上 `delayed: true`（文本也以 `[delayed]` 开头）。

## Telegram {#telegram}

```json
"notify": { "telegram_bot_token_env": "TELEGRAM_BOT_TOKEN", "telegram_chat_id": "-1001234567890" }
```

| 键 | 含义 |
|---|---|
| `telegram_bot_token_env` | 存放 bot token 的环境变量。 |
| `telegram_chat_id` | 目标聊天 ID。 |

只有当 token 变量非空**并且**设置了聊天 ID 时，该渠道才会启用。消息通过 Bot API 的 `sendMessage` 发送，并关闭链接预览；较长的报告会被拆成带编号的若干部分，每部分最多 4,096 个字符（Telegram 的上限）。

## JSONL 文件 {#jsonl-file}

```json
"notify": { "jsonl_file": "data/alerts.jsonl" }
```

每条消息都以一行 JSON 追加写入——供一个持续读取该文件并转发到聊天工具的桥接程序使用，或供日志采集器使用。相对路径相对于工作目录（在 Docker 中请使用 `/app/data/…` 或 `data/…`，让文件落在数据卷上）。目录不存在时会自动创建；文件以 `0644` 权限创建（告警不含密钥，而桥接程序常常以与容器不同的用户运行），每条记录都是一次 `O_APPEND` 写入，所以读取方永远不会读到半条记录。

**轮转（v1.18）。** 写入一条消息之前，如果文件已达到 **32 MB**，就会被重命名：`alerts.jsonl` → `alerts.jsonl.1` → `.2` → `.3`；最旧的副本被丢弃，因此最多保留 3 个轮转文件。轮转发生在两条消息之间，所以每个文件都只包含完整的行。按文件名跟踪的桥接程序（`tail -F`）会跟上新文件；持有旧文件描述符的程序会先把旧文件读到末尾。保存在 `charts/` 中的[附图](#charts-and-html-reportvisuals-default-on)在写入 **90 天**后删除，每天随日报执行一次；消息本身仍保留在归档中。这两个限制都不可配置。

记录字段：

| 字段 | 含义 |
|---|---|
| `ts` | 写入时间（UTC，RFC 3339） |
| `source` | 恒为 `"flarehound"` |
| `kind` | `intraday`、`daily`、`audit` 或 `heartbeat` |
| `zone` | zone 名称 |
| `decision` | 仅 intraday：`alert`、`changed`、`escalate` 或 `recovered`（为空时省略） |
| `window_from`、`window_to` | 评估的时间窗口（`audit` 消息为零值时间） |
| `rules` | 触发的信号键，例如 `dynamic_up`、`worker_calls_up:web`（为空时省略）；对 `heartbeat` 而言，是出错的 zone |
| `severity` | intraday 告警：`low`（被边缘吸收的洪峰）或 `high` |
| `delayed` | 从发件箱重发时为 `true`（否则省略） |
| `text` | 渲染后的消息 |

### 附图与 HTML（`report.visuals`，默认开启） {#charts-and-html-reportvisuals-default-on}

告警和日报会附带图表——最近 24 小时每小时的请求数，对照前一天，并给告警所在的小时加上阴影；当真实渲染（`dynamic`）是情况的一部分时（dynamic 或 CPU 指标越线，或者是被边缘吸收的低严重度洪峰——此时那条平坦的线正是证据），还会附上每小时的真实渲染量。图表在你的机器上用 Go 绘制；不会上传到任何地方。

| 渠道 | 收到什么 |
|---|---|
| 邮件 | 一封 HTML 邮件（multipart，附纯文本备选）：结论、指标卡片、内联图表、以条形图表示的贵贱分离、热门路径 / ASN / User-Agent，然后是完整的文本报告。 |
| Telegram | 先发文本，然后每张图表作为一张带说明的图片 |
| Discord | 先发文本，然后每张图表作为一个文件 |
| 企业微信 | 先发文本，然后每张图表作为一条图片消息（≤ 2 MB） |
| JSONL 文件 | 图表保存在该文件旁的 `charts/` 中，路径写在记录的 `images` 字段里 |
| Slack、飞书、通用 Webhook | 仅文本（它们的 webhook 机器人无法发送图片） |
| `-dry-run` | 图表和 HTML 保存到系统临时目录（`flarehound-preview/`），并打印其路径 |

从发件箱重发的消息只以文本发出。设置 `report.visuals: false` 可在所有渠道上只发文本。

### 心跳（死人开关） {#heartbeat-dead-man-switch}

从外面看，一个已经停摆的看守和一个平静的网站毫无区别。所以每个小时的每一轮——无论有没有异常——FlareHound 都会证明自己还活着：

- 写入 `data/heartbeat`（时间、版本、检查的 zone、错误、下一次运行时间）；
- 如果配置了 JSONL 文件，向其中追加一条 `kind: "heartbeat"` 记录；
- 访问 `notify.heartbeat_url_env`（一个 [healthchecks.io](https://healthchecks.io) 风格的 URL，来自环境变量）——成功时 `GET <url>`，有 zone 出错时 `GET <url>/fail`。一旦访问停止，外部服务就会向你告警。

心跳从不发往聊天渠道。Docker 镜像的 `HEALTHCHECK` 运行 `flarehound health`，当心跳早于两轮加 20 分钟时判定失败；admin 容器检查它自己的 `heartbeat-enforce`。`-dry-run` 不写心跳。

## Slack {#slack}

```json
"notify": { "slack_webhook_url_env": "SLACK_WEBHOOK_URL" }
```

使用 Slack 的 **incoming webhook**。载荷为 `{"text": …, "unfurl_links": false}`；长消息按 39,000 个字符拆分。

## Discord {#discord}

```json
"notify": { "discord_webhook_url_env": "DISCORD_WEBHOOK_URL" }
```

使用频道 webhook。载荷为 `{"content": …}`，并禁用 `allowed_mentions` 解析，因此告警正文永远不会 @ 到 `@everyone`。按 2,000 个字符拆分。

## 企业微信（WeCom） {#wecom}

```json
"notify": { "wecom_webhook_url_env": "WECOM_WEBHOOK_URL" }
```

使用群机器人 webhook，`msgtype: "text"`。按 **2,048 字节**拆分（企业微信的上限按字节计算，所以中文文本会更早被拆分）。HTTP 200 但 `errcode` 非零的响应视为失败，会进入重试和发件箱流程。

## 飞书 / Lark {#feishu-lark}

```json
"notify": { "feishu_webhook_url_env": "FEISHU_WEBHOOK_URL", "feishu_secret_env": "FEISHU_SECRET" }
```

| 键 | 含义 |
|---|---|
| `feishu_webhook_url_env` | 存放自定义机器人 URL 的环境变量。 |
| `feishu_secret_env` | 存放签名密钥的环境变量——仅当机器人启用了签名校验时需要。 |

发送 `msg_type: "text"`，按 4,000 个字符拆分。配置了密钥时，每个请求都带上 `timestamp`（Unix 秒）和 `sign` = base64(以 `timestamp + "\n" + secret` 为 key、对空消息做 HMAC-SHA256)。HTTP 200 但 `code` 非零的响应视为失败。

## 邮件（SMTP） {#email-smtp}

```json
"notify": {
  "email": {
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "tls": "starttls",
    "username": "alerts@example.com",
    "password_env": "SMTP_PASSWORD",
    "from": "FlareHound <alerts@example.com>",
    "to": ["ops@example.com"]
  }
}
```

| 键 | 含义 |
|---|---|
| `smtp_host` | 必填。 |
| `smtp_port` | 按模式取默认值：587（`starttls`）、465（`tls`）、25（`none`）。 |
| `tls` | `starttls`（默认）、`tls` 或 `none`。 |
| `username` | 可选；设置后，`password_env` 必须指向一个非空变量。 |
| `password_env` | 存放密码的环境变量。 |
| `from` | 必填。 |
| `to` | 必填，至少一个地址。 |

TLS 模式（SMTP）：

- **`starttls`**——先建立明文连接，再用 STARTTLS 升级。如果服务器不支持 STARTTLS，发送失败（绝不会悄悄退回明文）。
- **`tls`**——从第一个字节起就是隐式 TLS（通常为 465 端口）。
- **`none`**——不加密，仅用于本地中继。FlareHound 拒绝在这种连接上发送用户名和密码。

邮件为纯文本、UTF-8、base64 编码；主题取消息的第一行（最多 120 个字符），`X-FlareHound-Kind` 请求头携带 `kind`。认证使用 SMTP PLAIN。

### 通过 HTTPS 发送邮件（Resend） {#email-over-https-resend}

许多云主机会封锁出站 SMTP（25、465 和 587 端口）。设置 `"provider": "resend"` 后，同样的邮件改为发往 [Resend](https://resend.com) 的 HTTPS API（`https://api.resend.com/emails`，443 端口）：

```json
"notify": {
  "email": {
    "provider": "resend",
    "api_key_env": "RESEND_API_KEY",
    "from": "FlareHound <alerts@example.com>",
    "to": ["ops@example.com"]
  }
}
```

`from` 的域名必须在 Resend 中完成验证（首次测试也可以用 `onboarding@resend.dev`，它只能投递到你自己 Resend 账号的邮箱）。文本、HTML 和内联图表与通过 SMTP 发送时相同；Resend 每封邮件最多接受 50 个收件人。Resend 返回的错误会连同其消息一起记入日志（例如 `email: resend: HTTP 403: The example.com domain is not verified…`），但绝不包含 key。控制台发出的密码重置邮件也使用同一个提供方。

## Docker 中的密钥 {#secrets-in-docker}

每个 `*_env` 键都指向一个必须存在于**容器内部**的变量。把它加到 `docker-compose.yml` 的 `environment:` 中：

```yaml
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN:?}
      SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL:-}
      FEISHU_WEBHOOK_URL: ${FEISHU_WEBHOOK_URL:-}
      FEISHU_SECRET: ${FEISHU_SECRET:-}
```

对于 Slack、Discord、企业微信和飞书，如果指定的变量为空，FlareHound 会在启动时停止。对于 Webhook 和 Telegram，变量为空只是让该渠道保持关闭。
