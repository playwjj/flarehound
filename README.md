# FlareHound

**A self-hosted watchdog for websites behind Cloudflare.** It polls the Cloudflare Analytics API with a read-only token, detects traffic anomalies hour by hour, breaks them down by path / ASN / user agent / cache status, and sends you a short, plain-language report — conclusion first, with the evidence and a suggested action — only when something actually needs your attention.

Cloudflare gives you data. FlareHound gives you the conclusion.

> Status: **v0.1 skeleton**. The detection model, thresholds and alert discipline are ported from a real incident response (a residential-proxy crawler flood, 2026-11-17). Daily reports and the full intraday rule set land in v0.2–v0.3 — see [SPEC.md](SPEC.md) (in Chinese) for the full design.

## Why

- A crawler flood can start at 08:00 and burn Workers CPU for hours before a daily summary — or the invoice — shows it.
- Cloudflare's own smart anomaly tooling mostly lives on Enterprise plans. Pro / Business / Free users get raw dashboards.
- Generic uptime monitors check *whether* your site is up, not *what your traffic is doing*.

FlareHound watches the traffic itself:

- **Hourly anomaly watch** — the last full clock hour vs. the same hour yesterday: zone requests, uncached (`dynamic`) responses, origin 5xx, Worker invocations and CPU P50.
- **Attribution before conclusions** — every spike is split by path, ASN, user agent and cache status first, and "expensive" traffic (Worker renders, origin hits) is reported separately from cheap edge volume.
- **New-face detection** — user agents and ASNs that suddenly enter your Top 10 and weren't in yesterday's Top 25.
- **Quiet by design** — no anomaly, no message. The same anomaly never alerts twice unless it grows another 25%; two clean rounds earn a single "recovered" line.
- **Suggestions, never actions** — the watchdog core is read-only. It may suggest blocking an ASN or challenging a path, with evidence and expected impact, but it never changes your Cloudflare configuration. (Blocking an IP or CIDR becomes a one-click, separately authorized action in v0.5; a general action module follows in v0.7 — both behind their own write token and per-action confirmation; the core stays read-only.)
- **A memory Cloudflare doesn't keep** — Cloudflare retains only ~31 days of analytics, and raw logs are a metered add-on. FlareHound snapshots every check into a local SQLite archive, building the long memory the platform lacks: multi-week baselines, 90-day per-rule hit history, first-seen dates for ASNs and user agents.

## Quick start

```bash
docker compose up -d
```

1. Create a **read-only** Cloudflare API token (see below).
2. Copy `config.example.json` to `config.json`, fill in your zone ID and Worker names.
3. Put the token in the environment — never in the config file:

```bash
export CF_API_TOKEN=...
```

4. Point `notify.webhook_url` at any endpoint that accepts a JSON POST (Telegram/Slack/Discord bridges included), or configure the Telegram bot.

### Token permissions (read-only)

Create the token at *Cloudflare Dashboard → My Profile → API Tokens → Create Token → Custom token*:

- **Zone** → **Analytics: Read**, **Logs: Read** (for each zone you monitor)
- **Account** → **Workers Scripts: Read**, **Account Analytics: Read**

FlareHound only ever calls `api.cloudflare.com/client/v4/graphql`. Your token never leaves your machine and is never written to disk or logs by the program.

## How it decides

Default alert lines (all configurable — these are the battle-tested values from the incident the tool is based on):

| Signal | Default |
|---|---|
| Worker invocations vs. yesterday | +35% |
| Zone requests vs. yesterday | +35% |
| Worker CPU P50 vs. yesterday | +25% |
| Dynamic (uncached) responses vs. yesterday | +50% |
| Origin 5xx | 3× baseline **and** > 50 |
| New face in Top 10 (UA or ASN) | > 5,000 requests/hour |
| Collapse in requests or invocations | −50% |

Known false-positive class handled out of the box: legitimate crawlers (e.g. Googlebot) bump their user-agent version strings and trip "new face" — FlareHound verifies them by ASN before attributing a surge.

## Deployment

The primary form factor is a single Go binary in a Docker container, running on **your own** VPS, home server or NAS — deliberately *not* on Cloudflare itself, so the watchdog has no blind spot when the platform it watches is the thing in trouble. The engine only needs outbound HTTPS and a local state file; a Cloudflare Workers (Cron Triggers) deployment adapter is on the roadmap as an alternative.

## Roadmap

- **v0.2** — daily digest (24 h comparison + fixed checkpoints)
- **v0.3** — full intraday watch (new-face detection, escalation/recovery state machine, attribution queries)
- **v0.4** — suggestion engine (block / challenge / rate-limit / cache candidates)
- **v0.5** — one-click IP / CIDR blocklist (block from an alert or the CLI, expiring blocks, guard rails, audit log)
- **v0.6** — WAF rule audit (coverage gaps on sensitive paths, ordering/redundancy issues, per-rule hit stats, over-broad exemptions)
- **v0.7** — general action module (execute approved suggestions with a separate write token, pre-change backup, read-back verification)
- **v0.8** — more notification channels, multi-zone
- **v1.0** — calibration tooling against dashboard numbers, docs site

Full specification: [SPEC.md](SPEC.md) (Chinese).

## Limitations

- Cloudflare's GraphQL Analytics is sampled and has no host / country / referer dimensions; very large sites will find attribution too coarse. FlareHound targets small-to-medium sites.
- Analytics ingestion lag (~5–10 min) sets the detection floor. This is a watchdog, not a real-time shield — edge rules remain the shield.
- The local archive stores hourly aggregates, not raw request logs; it cannot reconstruct individual requests, and history starts accumulating only from the day you deploy.

## License

MIT © 2026 playwjj
