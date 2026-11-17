# Configuration reference

FlareHound reads one JSON file (`-config`, default `config.json`). Every key is optional unless marked required; a key left out keeps its default — a missing threshold is never treated as 0. Secrets are never stored in the file: `*_env` keys name the environment variable that holds the value.

A complete example is `config.example.json` in the repository. Validation errors stop the process at startup with a message naming the key.

## cloudflare

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cloudflare.account_id` | string | `""` | 32-char hex account ID. Required when any zone lists `workers`. Also used by blocking for the account IP list (without it, IP blocks use an expression rule). |
| `cloudflare.api_token_env` | string | `"CF_API_TOKEN"` | Environment variable holding the **read** token. Startup fails if it is empty. |
| `cloudflare.zones` | array | — | **Required**, at least one zone. |
| `cloudflare.zones[].zone_id` | string | — | **Required.** 32-char hex zone ID. |
| `cloudflare.zones[].name` | string | the zone ID | Display name; also the default WAF-audit probe host and the `--zone` selector. |
| `cloudflare.zones[].workers` | string[] | `[]` | Worker script names to watch (invocations and CPU P50). Each is evaluated separately. Needs Account Analytics: Read. |

## schedule

| Key | Type | Default | Meaning |
|---|---|---|---|
| `schedule.intraday_interval` | duration | `"1h"` | Watch interval and window length. Must be a whole number of hours (windows are full clock hours). |
| `schedule.intraday_offset` | duration | `"7m"` | How long after the hour boundary the check runs, absorbing analytics ingestion lag. Must be within `[0, 1h)`. |
| `schedule.settle_delay` | duration | `"3m"` | Wait before re-reading a window that looks collapsed, to tell ingestion lag from a real drop. |
| `schedule.daily_report_at` | `"HH:MM"` | `"08:00"` | Local time of the daily report. Empty string disables it. |
| `schedule.timezone` | string | host local time | IANA name, e.g. `"Asia/Shanghai"`. The image embeds the zone database. |
| `schedule.max_parallel_zones` | int | `4` | How many zones are checked at once. Allowed: 1–16. |

Durations use Go syntax (`90s`, `7m`, `2h`).

## thresholds

Detection lines; see [Detection](detection.md) for how each is applied.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `thresholds.total_up_pct` | number | `35` | Zone requests vs. baseline, % increase. |
| `thresholds.worker_calls_up_pct` | number | `35` | Worker invocations, % increase. |
| `thresholds.cpu_p50_up_pct` | number | `25` | Worker CPU P50, % increase. |
| `thresholds.dynamic_up_pct` | number | `50` | Uncached (`dynamic`) responses, % increase. |
| `thresholds.origin_5xx_multiplier` | number | `3` | Origin 5xx must reach this multiple of the baseline … |
| `thresholds.origin_5xx_min` | int | `50` | … and exceed this absolute count. |
| `thresholds.new_face_min_count` | int | `5000` | A new user agent / ASN in the Top 10 must exceed this many requests in the window. |
| `thresholds.collapse_down_pct` | number | `50` | Requests or invocations, % drop. |
| `thresholds.min_count` | int | `1000` | Volume floor for percentage rules: the current window (rises) or baseline (drops) must reach it; CPU P50 needs both windows' invocations ≥ it. |
| `thresholds.escalation_pct` | number | `25` | An already reported signal re-alerts only after growing this % past its reported peak. |
| `thresholds.recovery_clean_rounds` | int | `2` | Consecutive clean rounds before the "recovered" message. |

## path_rules

Per-path lines for sensitive, low-volume paths whose anomalies would drown in zone totals.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path_rules[].name` | string | the path | Signal name in alerts. |
| `path_rules[].path` | string | — | **Required.** Must start with `/`; `*` is a wildcard (`/login*`). |
| `path_rules[].up_pct` | number | `100` | % increase vs. baseline. |
| `path_rules[].min_count` | int | `20` | Volume floor in the current window. |
| `path_rules[].dynamic_only` | bool | `false` | Count only uncached (`dynamic`) requests — the path's real rendering load. |

Path rules are also sensitive paths for suggestions and the [WAF audit](audit.md). Each one adds a query per window.

## daily

Fixed checkpoints of the [daily report](reports.md#daily-report).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `daily.paths[].label` | string | the path | Checkpoint name. |
| `daily.paths[].path` | string | — | **Required.** Must start with `/`; `*` wildcard. Also a sensitive path. |
| `daily.paths[].max` | int | `0` | Maximum origin reach (requests not served from edge cache) over 24 h; above it the line is marked ⚠. |
| `daily.artifacts[].label` | string | `""` | Name of a known accounting artifact. |
| `daily.artifacts[].path` | string | `""` | Path pattern (`*` wildcard). |
| `daily.artifacts[].edge_status` | int | `0` | Edge status to count (e.g. `504`); `0` counts any status. |

## known_faces

Sources that never count as new faces.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `known_faces.asns` | int[] | `[]` | ASNs (your monitors, partners, your own services). |
| `known_faces.user_agents` | string[] | `[]` | Case-insensitive user-agent substrings. |

## rule_names

| Key | Type | Default | Meaning |
|---|---|---|---|
| `rule_names` | object | `{}` | Map of firewall rule ID → display name in reports. With WAF: Read, names come from the rule descriptions automatically; this map overrides them. |

## report

| Key | Type | Default | Meaning |
|---|---|---|---|
| `report.language` | string | `"en"` | `"en"` or `"zh"` (Chinese). |

## notify

All channels are optional and can be combined; with none configured, findings appear only in the log. Details per channel: [Notification channels](channels.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `notify.webhook_url_env` | string | `""` | Variable holding a generic webhook URL. Takes precedence over `webhook_url`. |
| `notify.webhook_url` | string | `""` | Plain-text webhook URL, kept for compatibility. Prefer `webhook_url_env`. |
| `notify.telegram_bot_token_env` | string | `""` | Variable holding the Telegram bot token. |
| `notify.telegram_chat_id` | string | `""` | Telegram chat ID. Telegram is active only when both are set. |
| `notify.jsonl_file` | string | `""` | Append every message as one JSON line to this file. |
| `notify.slack_webhook_url_env` | string | `""` | Variable holding a Slack incoming-webhook URL. |
| `notify.discord_webhook_url_env` | string | `""` | Variable holding a Discord webhook URL. |
| `notify.wecom_webhook_url_env` | string | `""` | Variable holding a WeCom (企业微信) group-bot URL. |
| `notify.feishu_webhook_url_env` | string | `""` | Variable holding a Feishu / Lark custom-bot URL. |
| `notify.feishu_secret_env` | string | `""` | Variable holding the Feishu signing secret (optional). |
| `notify.email` | object | absent | SMTP channel; see below. |

For Slack, Discord, WeCom and Feishu, naming a variable that is empty is a startup error.

`notify.email`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `smtp_host` | string | — | **Required.** |
| `smtp_port` | int | by `tls`: 587 / 465 / 25 | SMTP port. |
| `tls` | string | `"starttls"` | `starttls`, `tls` (implicit TLS) or `none` (local relays only). |
| `username` | string | `""` | SMTP user; when set, `password_env` must name a non-empty variable. |
| `password_env` | string | `""` | Variable holding the SMTP password. |
| `from` | string | — | **Required.** Sender address. |
| `to` | string[] | — | **Required**, at least one recipient. |

## state_file

| Key | Type | Default | Meaning |
|---|---|---|---|
| `state_file` | string | `"data/state.json"` | Alert state machine file. With several zones, each zone gets its own file derived from it (`data/state-example-com.json`). Its directory is the **data directory**: the notification outbox (`outbox.json`), rule backups (`backups/`) and the default archive live there. Relative paths are relative to the working directory (`/app` in the image). |

## blocking

| Key | Type | Default | Meaning |
|---|---|---|---|
| `blocking.write_token_env` | string | `"CF_WRITE_TOKEN"` | Variable holding the separate write token. Must differ from `cloudflare.api_token_env`. Read only by blocking and rule-change commands. |
| `blocking.never_block` | string[] | `[]` | IPs / CIDRs that are never blocked or offered as block candidates. Each must parse as an IP or CIDR. |
| `blocking.never_block_asns` | int[] | `[]` | ASNs never blocked or suggested for blocking. |

## waf_audit

| Key | Type | Default | Meaning |
|---|---|---|---|
| `waf_audit.disabled` | bool | `false` | Turn the WAF audit off (daily section, re-audit on change, `flarehound audit`). |
| `waf_audit.hosts` | string[] | the zone name | Hosts to probe; rules often pin `http.host`, so coverage is judged per host. |
| `waf_audit.sensitive_paths` | string[] | `[]` | Extra sensitive path patterns, in addition to `path_rules` and `daily.paths`. |

## archive

| Key | Type | Default | Meaning |
|---|---|---|---|
| `archive.disabled` | bool | `false` | Turn the local SQLite archive off. `-backfill`, `block --for` and the rule-change commands need it. |
| `archive.file` | string | `<data dir>/archive.db` | Archive path. |
| `archive.hourly_retention_days` | int | `400` | Days to keep hourly snapshots (about 13 months). Minimum 30. Daily snapshots, faces and alerts are kept forever. |

## Environment variables at a glance

| Variable (default name) | Set by key | Used by |
|---|---|---|
| `CF_API_TOKEN` | `cloudflare.api_token_env` | Watchdog and all commands |
| `CF_WRITE_TOKEN` | `blocking.write_token_env` | `block`, `unblock`, `blocks`, `enforce`, `rules`, `ratelimit`, `cache` |
| *(your names)* | `notify.*_env`, `notify.email.password_env` | Notification channels |
