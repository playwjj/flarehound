# FlareHound

**A self-hosted traffic console and watchdog for websites behind Cloudflare.** FlareHound polls the Cloudflare Analytics API with a read-only token, compares each clock hour with the same hour yesterday, breaks every anomaly down by path, ASN, user agent and cache status, and sends a short, plain-language report — conclusion first, with evidence and a suggested action — only when something needs your attention.

Cloudflare gives you data. FlareHound gives you the conclusion.

## What it does

| Feature | Summary | Page |
|---|---|---|
| Hourly watch | Zone requests, uncached (`dynamic`) responses, origin 5xx, Worker invocations and CPU P50, new user agents / ASNs, per-path lines | [Detection](detection.md) |
| Quiet alerting | One alert per anomaly; another only on a new signal or +25% growth; one "recovered" line after two clean rounds | [Detection](detection.md#alert-discipline) |
| Attribution and suggestions | Expensive vs. cheap traffic, hypotheses with confidence and falsifiers, block / challenge / rate-limit / cache suggestions with paste-ready expressions | [Reports](reports.md) |
| Daily report | Last 24 h vs. the 24 h before, fixed checkpoints, firewall events, block attempts, WAF audit summary, calibration line | [Reports](reports.md#daily-report) |
| Notification channels | Webhook, Telegram, JSONL file, Slack, Discord, WeCom, Feishu/Lark, email | [Channels](channels.md) |
| Local archive | SQLite file with ~13 months of hourly snapshots, a 4-week median baseline, face history, alert history | [Archive](archive.md) |
| Calibration | How FlareHound's numbers relate to the Cloudflare dashboard | [Archive](archive.md#calibration) |
| One-click blocking | IP / CIDR / ASN / country / user agent, with guard rails, expiry and an audit log (separate write token) | [Blocking](blocking.md) |
| Rule changes | Add, edit, move, delete and restore custom, rate-limit and cache rules with backup and read-back (separate write token) | [Rule changes](rules.md) |
| WAF rule audit | Coverage gaps on sensitive paths, shadowed rules, forgeable exemptions, zombie rules, quota | [WAF audit](audit.md) |
| Web console | Live hour vs baseline, movers and drill-down, new faces, history, WAF audit and rules, settings, in-console blocking, snapshots, multi-zone home (admin / viewer accounts, TOTP, Google / GitHub sign-in) | [Console](console.md) |

## Design principles

- **Read-only core.** The watchdog process holds only a read token. Blocking and rule changes are separate commands with their own write token and an explicit confirmation.
- **Silence is a feature.** No anomaly, no message.
- **Split before concluding.** Every spike is attributed before any hypothesis is stated; findings are deterministic and reproducible — no AI sits in the detection path.
- **Your token stays home.** Tokens come only from environment variables, are redacted from logs, and are only sent to `api.cloudflare.com`.

## Where to start

1. [Quick start](quickstart.md) — run it with Docker in a few minutes.
2. [API tokens & permissions](permissions.md) — the minimum token you need.
3. [Configuration reference](configuration.md) — every key and default.

The full design (in Chinese) is in [SPEC.md](https://github.com/playwjj/flarehound/blob/main/SPEC.md). A short Chinese overview is on the [中文简介](zh.md) page.
