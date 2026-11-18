# Notification channels

Configure any number of channels under `notify`; every message goes to all of them. With no channel configured, FlareHound logs a warning and findings appear only in its log.

## Delivery guarantees (all channels)

- Each send is tried **3 times** with exponential backoff (2 s, then 4 s).
- A message that still fails is parked **per channel** in `outbox.json` in the data directory and re-sent at the start of the next round, prefixed with `[delayed]`.
- Queued messages older than **48 hours** are dropped with a log line — a two-day-old alert is noise.
- HTTP channels time out after 30 seconds; a non-2xx status is a failure.
- Error messages never contain the endpoint URL (bot URLs embed secrets). All channel secrets are redacted from logs.
- Channels that split long messages number the parts `(i/n)`; split points prefer line breaks, and an over-long single line is cut on a character boundary (never inside a multi-byte character).

| Channel | Size handling |
|---|---|
| Webhook, JSONL file, email | Whole message |
| Telegram | Split at 4,096 characters |
| Slack | Split at 39,000 characters |
| Discord | Split at 2,000 characters |
| WeCom | Split at 2,048 bytes |
| Feishu / Lark | Split at 4,000 characters |

`-dry-run` replaces every channel with stdout.

## Generic webhook

```json
"notify": { "webhook_url_env": "FLAREHOUND_WEBHOOK_URL" }
```

| Key | Meaning |
|---|---|
| `webhook_url_env` | Variable holding the URL (preferred). If set, it takes precedence over `webhook_url`. |
| `webhook_url` | Plain URL in the config file, kept for compatibility. |

FlareHound POSTs `Content-Type: application/json`:

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

`text` is the primary field, so receivers that read only `text` keep working. `decision` and `rules` are omitted when empty; `delayed: true` is added for messages re-sent from the outbox (the text also starts with `[delayed]`).

## Telegram

```json
"notify": { "telegram_bot_token_env": "TELEGRAM_BOT_TOKEN", "telegram_chat_id": "-1001234567890" }
```

| Key | Meaning |
|---|---|
| `telegram_bot_token_env` | Variable holding the bot token. |
| `telegram_chat_id` | Target chat ID. |

The channel is active only when the token variable is non-empty **and** a chat ID is set. Messages go to the Bot API `sendMessage` with link previews disabled; longer reports are split into numbered parts of at most 4,096 characters (Telegram's limit).

## JSONL file

```json
"notify": { "jsonl_file": "data/alerts.jsonl" }
```

Every message is appended as one JSON line — for a bridge that tails the file into a chat, or a log shipper. Relative paths are relative to the working directory (in Docker use `/app/data/…` or `data/…` so it lands on the volume). The directory is created if needed; the file is created with mode `0644` (alerts hold no secrets, and a bridge often runs as a different user than the container), and each record is a single `O_APPEND` write, so a reader never sees half a record.

Record fields:

| Field | Meaning |
|---|---|
| `ts` | Time written (UTC, RFC 3339) |
| `source` | Always `"flarehound"` |
| `kind` | `intraday`, `daily`, `audit` or `heartbeat` |
| `zone` | Zone name |
| `decision` | Intraday only: `alert`, `changed`, `escalate` or `recovered` (omitted when empty) |
| `window_from`, `window_to` | The evaluated window (zero time for `audit` messages) |
| `rules` | Signal keys that fired, e.g. `dynamic_up`, `worker_calls_up:web` (omitted when empty); for `heartbeat`, the zones that errored |
| `severity` | Intraday alerts: `low` (a flood absorbed at the edge) or `high` |
| `delayed` | `true` when re-sent from the outbox (omitted otherwise) |
| `text` | The rendered message |

### Charts and HTML (`report.visuals`, default on)

Alerts and daily reports come with charts — requests per hour over the last 24 hours against the day before, with the alert's hour shaded, plus real rendering (`dynamic`) per hour when it is part of the story (a dynamic or CPU line crossed, or a low-severity edge-absorbed flood, where the flat line is the proof). Charts are drawn in Go on your machine; nothing is uploaded anywhere.

| Channel | What it gets |
|---|---|
| Email | An HTML message (multipart with a plain-text alternative): verdict, metric tiles, inline charts, the cost split as a bar, top paths / ASNs / user agents, then the full text report. |
| Telegram | The text, then each chart as a photo with a caption |
| Discord | The text, then each chart as a file |
| WeCom | The text, then each chart as an image message (≤ 2 MB) |
| JSONL file | Charts saved next to the file in `charts/`, their paths in the record's `images` field |
| Slack, Feishu, generic webhook | Text only (their webhook bots cannot post images) |
| `-dry-run` | Charts and the HTML saved to the system temp directory (`flarehound-preview/`) with their paths printed |

Messages re-sent from the outbox go out as text. Set `report.visuals: false` for text only everywhere.

### Heartbeat (dead-man switch)

A dead watchdog and a quiet site look the same from outside. So every hourly round — anomaly or not — FlareHound proves it is alive:

- writes `data/heartbeat` (time, version, zones checked, errors, next run);
- appends a `kind: "heartbeat"` record to the JSONL file, if configured;
- pings `notify.heartbeat_url_env` (a [healthchecks.io](https://healthchecks.io)-style URL, from an environment variable) — `GET <url>` on success, `GET <url>/fail` when a zone errored. When the pings stop, the external service alerts you.

Heartbeats never go to chat channels. The Docker image's `HEALTHCHECK` runs `flarehound health`, which fails when the heartbeat is older than two rounds plus 20 minutes; the admin container checks its own `heartbeat-enforce`. `-dry-run` writes no heartbeat.

## Slack

```json
"notify": { "slack_webhook_url_env": "SLACK_WEBHOOK_URL" }
```

Uses a Slack **incoming webhook**. Payload `{"text": …, "unfurl_links": false}`; long messages are split at 39,000 characters.

## Discord

```json
"notify": { "discord_webhook_url_env": "DISCORD_WEBHOOK_URL" }
```

Uses a channel webhook. Payload `{"content": …}` with `allowed_mentions` parsing disabled, so an alert body can never ping `@everyone`. Split at 2,000 characters.

## WeCom (企业微信)

```json
"notify": { "wecom_webhook_url_env": "WECOM_WEBHOOK_URL" }
```

Uses a group-bot webhook with `msgtype: "text"`. Split at **2,048 bytes** (WeCom's limit is in bytes, so Chinese text splits sooner). A response with HTTP 200 but a non-zero `errcode` counts as a failure and goes through retry and the outbox.

## Feishu / Lark (飞书)

```json
"notify": { "feishu_webhook_url_env": "FEISHU_WEBHOOK_URL", "feishu_secret_env": "FEISHU_SECRET" }
```

| Key | Meaning |
|---|---|
| `feishu_webhook_url_env` | Variable holding the custom-bot URL. |
| `feishu_secret_env` | Variable holding the signing secret — only if the bot has signature verification enabled. |

Sends `msg_type: "text"`, split at 4,000 characters. With a secret, each request carries `timestamp` (Unix seconds) and `sign` = base64(HMAC-SHA256 with key `timestamp + "\n" + secret` over an empty message). A response with HTTP 200 but a non-zero `code` counts as a failure.

## Email (SMTP)

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

| Key | Meaning |
|---|---|
| `smtp_host` | Required. |
| `smtp_port` | Default by mode: 587 (`starttls`), 465 (`tls`), 25 (`none`). |
| `tls` | `starttls` (default), `tls` or `none`. |
| `username` | Optional; when set, `password_env` must name a non-empty variable. |
| `password_env` | Variable holding the password. |
| `from` | Required. |
| `to` | Required, at least one address. |

TLS modes (SMTP):

- **`starttls`** — plain connection upgraded with STARTTLS. If the server does not offer STARTTLS, sending fails (it never silently falls back to plain text).
- **`tls`** — implicit TLS from the first byte (typically port 465).
- **`none`** — no encryption, for a local relay only. FlareHound refuses to send a username and password over it.

The mail is plain text, UTF-8, base64-encoded; the subject is the message's first line (up to 120 characters), and an `X-FlareHound-Kind` header carries the `kind`. Authentication uses SMTP PLAIN.

### Email over HTTPS (Resend)

Many cloud hosts block outbound SMTP (ports 25, 465 and 587). With `"provider": "resend"` the same mail goes to [Resend](https://resend.com)'s HTTPS API (`https://api.resend.com/emails`, port 443) instead:

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

The `from` domain must be verified in Resend (or use `onboarding@resend.dev` for a first test, which only delivers to your own Resend account's address). Text, HTML and inline charts are the same as over SMTP; Resend accepts at most 50 recipients per message. An error from Resend is logged with its message (e.g. `email: resend: HTTP 403: The example.com domain is not verified…`), never with the key. Password-reset mails from the console use the same provider.

## Secrets in Docker

Each `*_env` key names a variable that must exist **inside the container**. Add it to `environment:` in `docker-compose.yml`:

```yaml
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN:?}
      SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL:-}
      FEISHU_WEBHOOK_URL: ${FEISHU_WEBHOOK_URL:-}
      FEISHU_SECRET: ${FEISHU_SECRET:-}
```

For Slack, Discord, WeCom and Feishu, a named variable that is empty stops FlareHound at startup. For the webhook and Telegram, an empty variable simply leaves that channel off.
