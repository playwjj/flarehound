# Troubleshooting

Start with **`flarehound doctor`**: it checks the configuration, what each token can reach (naming any missing permission), the plan's capabilities, the heartbeat and the archive in one go.

FlareHound logs to stderr; in Docker use `docker compose logs -f flarehound`. Secrets are redacted from all log output. If the container shows `unhealthy`, the watch loop's heartbeat is stale — see the log.

## Startup errors

| Message (abridged) | Fix |
|---|---|
| `environment variable CF_API_TOKEN is empty` | Export the read token, and pass it to the container. |
| `zones[0].zone_id … is not a 32-char hex Cloudflare zone ID` | Copy the zone ID from the zone's Overview page. |
| `account_id … (required to watch Workers)` | Set `cloudflare.account_id` or remove `workers`. |
| `schedule.intraday_interval must be a whole number of hours` | Use `1h`, `2h`, … |
| `schedule.intraday_offset must be within [0, 1h)` | E.g. `7m`. |
| `schedule.daily_report_at … must be HH:MM` | E.g. `"08:00"`, or `""` to disable. |
| `notify.slack_webhook_url_env names X, but that environment variable is empty` | Set the variable (inside the container) or remove the key. Same for Discord, WeCom, Feishu. |
| `notify.email needs smtp_host, from and at least one to` | Complete the `email` block. |
| `notify.email.password_env must name a non-empty environment variable when username is set` | Set the password variable. |
| `notify.email.api_key_env must name a non-empty environment variable for provider resend` | Set the Resend API key variable. |
| `blocking.write_token_env must differ from cloudflare.api_token_env` | Keep the two tokens in different variables. |
| `archive.hourly_retention_days must be >= 30` | The long baseline needs 28 days. |
| `warning: no notification channel configured` | Not an error: findings only go to the log. Configure a [channel](channels.md). |

## Access and plan

- **`the token cannot see this zone/account`** — the token is not scoped to that zone, or (with `workers`) lacks Account → Account Analytics: Read for that account.
- **`not available on this plan, degraded: clientAsn, clientASNDescription, firewall events`** — normal on Free. See [Limitations](limitations.md#plans).
- **`capability probe failed, assuming full analytics`** — the probe query failed; FlareHound carries on and retries next round. If later queries fail on missing fields, check the token and plan.
- **WAF audit "unavailable … lacks Zone → WAF: Read"** — add WAF: Read to the read token, or set `waf_audit.disabled`.

## No messages

- **Silence is the default.** No anomaly, no message — only the daily report is sent every day. Look for `quiet (findings=0, active=false)` in the log.
- **`window … already evaluated, skipping`** — each window is evaluated once; a restart or an earlier `-once` run already did it. `-dry-run` runs do not count: they print instead of sending and leave no trace (no state file write, no alert history), so the real run that follows still evaluates the window.
- **Delivery failures** — failed messages are queued in `data/outbox.json` and re-sent next round with `[delayed]`; messages older than 48 hours are dropped with a log line. Check the logged error (`HTTP 4xx`, `wecom errcode …`, `feishu code …`, `email: …`).
- **Telegram** sends only when both the token variable and `telegram_chat_id` are set; a webhook or Telegram variable that is empty silently leaves that channel off.
- **Email** — `server does not offer STARTTLS`: use `"tls": "tls"` (port 465) or, for a local relay only, `"none"`. Credentials are never sent over `none`. `connect: … i/o timeout` usually means the host blocks outbound SMTP — switch to `"provider": "resend"` (HTTPS).

## Numbers look wrong

- **Higher than the dashboard** — expected; run `flarehound calibrate`. See [Calibration](archive.md#calibration).
- **Many 504 / 5xx at the edge but visitors are fine** — likely cache-operation artifacts; list them under [`daily.artifacts`](configuration.md#daily).
- **A collapse "withheld: window still filling"** — the re-read after `settle_delay` still grew; the data was not settled yet. Raise `schedule.intraday_offset` if this is frequent.
- **Too many alerts on a small site** — raise `thresholds.min_count`; register your own monitors under `known_faces`.

## Blocking and rule changes

- **`environment variable CF_WRITE_TOKEN is empty`** — blocking and rule commands need the separate write token. In Docker, use the `flarehound-admin` service.
- **`cannot read DNS records to protect your origin IPs`** — grant Zone → DNS: Read to the write token, or pass `--skip-origin-check` if you are sure.
- **`custom-rule quota is full`** — unblock stale entries, merge rules (see the [audit's quota section](audit.md#quota)), or grant Zone → WAF: Edit so the IP Access Rules fallback can be used for IPs and ASNs.
- **`--for needs the archive`** / **`the execution module needs the archive`** — set `archive.disabled` to false.
- **`rule changes have no --yes`** — by design; confirm interactively.
- **Expired blocks not lifted** — the console must hold the write token (it lifts them every 5 minutes), or `flarehound enforce` must be running (`docker compose --profile admin up -d`). The blocks page warns when neither is.
- **A read-back mismatch** after a rule change — the error includes `flarehound rules restore <id>`; compare with the dashboard first.
