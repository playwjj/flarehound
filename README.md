# FlareHound

**A self-hosted watchdog for websites behind Cloudflare.** It polls the Cloudflare Analytics API with a read-only token, detects traffic anomalies hour by hour, breaks them down by path / ASN / user agent / cache status, and sends you a short, plain-language report — conclusion first, with the evidence and a suggested action — only when something actually needs your attention.

Cloudflare gives you data. FlareHound gives you the conclusion.

> Status: **v0.5** — hourly watch, daily report, suggestion engine, local archive and one-click blocking are complete. The detection model, thresholds and alert discipline are ported from a real incident response (a residential-proxy crawler flood, 2026-11-17). Next up: one-click blocking (v0.5). See [SPEC.md](SPEC.md) (in Chinese) for the full design.

## Why

- A crawler flood can start at 08:00 and burn Workers CPU for hours before a daily summary — or the invoice — shows it.
- Cloudflare's own smart anomaly tooling mostly lives on Enterprise plans. Pro / Business / Free users get raw dashboards.
- Generic uptime monitors check *whether* your site is up, not *what your traffic is doing*.

FlareHound watches the traffic itself:

- **Hourly anomaly watch** — the last full clock hour vs. the same hour yesterday: zone requests, uncached (`dynamic`) responses, origin 5xx, Worker invocations and CPU P50.
- **Attribution before conclusions** — every spike is split by path, ASN, user agent and cache status first, and "expensive" traffic (Worker renders, origin hits) is reported separately from cheap edge volume.
- **New-face detection** — user agents and ASNs that suddenly enter your Top 10 and weren't in yesterday's Top 25.
- **Quiet by design** — no anomaly, no message. The same anomaly never alerts twice unless it grows another 25%; two clean rounds earn a single "recovered" line.
- **Suggestions, never actions** — the watchdog core is read-only. It may suggest blocking an ASN or challenging a path, with evidence and expected impact, but it never changes your Cloudflare configuration. (Blocking an IP, range, ASN, country or user-agent becomes a one-click, separately authorized action in v0.5; a general action module follows in v0.7 — both behind their own write token and per-action confirmation; the core stays read-only.)
- **A memory Cloudflare doesn't keep** — Cloudflare retains only ~31 days of analytics, and raw logs are a metered add-on. FlareHound snapshots every check into a local SQLite file (`data/archive.db`, ~13 months of hourly snapshots, daily rollups forever), building the long memory the platform lacks. Once four weeks are archived, a spike must beat both yesterday *and* the 4-week same-hour median before it alerts — one odd yesterday no longer pages you. New ASNs and user agents are reported with their first-seen date, and every alert is kept in a history table.

## Quick start

Releases are published to Docker Hub as multi-arch images (`linux/amd64`, `linux/arm64`) on every `v*` tag, e.g. `passport888/flarehound:0.1.0`. The `docker-compose.yml` in this repo pulls the published image (or builds it locally from source if you prefer).

```bash
docker compose up -d
```

1. Create a **read-only** Cloudflare API token (see below).
2. Copy `config.example.json` to `config.json`, fill in your zone ID and Worker names.
3. Put the token in the environment — never in the config file:

```bash
export CF_API_TOKEN=...
```

4. Point `notify.webhook_url_env` at an environment variable holding any endpoint that accepts a JSON POST (Telegram/Slack/Discord bridges included), or configure the Telegram bot.
5. Pick the report language: `"report": {"language": "en"}` or `"zh"` (Chinese).

Optionally fill the local archive with the last four weeks right away (Cloudflare keeps ~31 days), so the 4-week baseline works from day one instead of week five. It is paced to ~1 query/second and takes about an hour per zone:

```bash
flarehound -config config.json -backfill 28
```

Try it before going live — this prints the messages instead of sending them:

```bash
flarehound -config config.json -once -dry-run    # one hourly check
flarehound -config config.json -daily -dry-run   # today's daily report
```

### What a message looks like

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

**Suggestions** come with evidence, expected gain, blast radius, rollback and a paste-ready rule expression. Only cloud/datacenter ASNs are ever suggested for blocking; residential, mobile, backbone and unknown networks get a *challenge* suggestion instead. No suggestion is made when the evidence is thin, or when the surge is mostly cheap edge-cached traffic.

### Token permissions (read-only)

Create the token at *Cloudflare Dashboard → My Profile → API Tokens → Create Token → Custom token*:

- **Zone** → **Analytics: Read**, **Logs: Read**, **Zone: Read** (for each zone you monitor)
- **Account** → **Workers Scripts: Read**, **Account Analytics: Read**

Optional add-ons — grant only when you enable the feature:

- **WAF rule audit** (v0.6): add **Zone** → **WAF: Read** and **Firewall Services: Read** to the same token.
- **One-click blocking** (v0.5): create a *separate* write token — **Account** → **Account Filter Lists: Edit**; **Zone** → **WAF: Edit**, **Firewall Services: Edit**, **DNS: Read**, **Zone: Read**. Put it in `CF_WRITE_TOKEN`. Never merge it into the read token; the watchdog process never holds it.

The watchdog's analytics run through `api.cloudflare.com/client/v4/graphql`; the audit additionally reads rulesets through the REST API on the same host. Your token never leaves your machine and is never written to disk or logs by the program.

## One-click blocking

Alerts name the culprit and print the command that blocks it:

```bash
flarehound block asn 207990 --action block --for 24h
flarehound block ip 45.13.7.9
flarehound block country XX --action challenge
flarehound block ua "BadBot/1.0" --for 7d --reason "scraper, 11-17 incident"
flarehound unblock asn 207990
flarehound blocks            # everything blocked, with 7-day attempts and expiry
flarehound enforce           # long-running: lifts blocks whose --for has passed
```

Before anything changes you see the exact plan — the rule it edits and the expression afterwards, the custom-rule quota, the target's measured share of the last hour's excess, and every warning — and confirm once. FlareHound only ever edits its own objects (rules named `flarehound-…`, the IP list `flarehound_block`), merges each target type into one rule so your quota is barely touched, keeps verified search bots allowed on ASN and country rules, and reads the result back to verify. It refuses to block Cloudflare's ranges, your origin IPs (from DNS), private ranges and anything on your `blocking.never_block` list. Blocking a residential/backbone ASN or a whole country requires retyping the ASN or country code. Every action lands in an append-only audit log, and the daily report lists each block's attempts — lift a block when the attempts stop, not when it gets quiet.

In Docker: `docker compose --profile admin up -d` starts the enforcer with the write token, and `docker compose run --rm flarehound-admin block …` runs commands.

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
| Collapse in requests or invocations | −50% (re-read after 3 min; still-arriving data is never called a collapse) |
| Volume floor for percentage rules | 1,000 requests per window |

Per-path overrides (`path_rules`) put a tighter line on sensitive low-volume paths like `/login*`.

Known false-positive class handled out of the box: legitimate crawlers (Googlebot, Bingbot, Applebot, YandexBot, Baiduspider) bump their user-agent version strings and trip "new face" — FlareHound checks that ≥ 90% of that UA's traffic comes from the crawler's own ASN before excluding it, so impostors still alert. Register your own monitors and services under `known_faces`.

**Alert discipline:** one alert when an anomaly starts; one more only if it shows a *new* signal or a reported signal grows another 25%; one line when two clean rounds pass. Failed deliveries are retried 3 times and then queued on disk for the next round.

**Daily report** (default 08:00 local): last 24 h vs the 24 h before, cache-cost split, top paths / ASNs / user agents with new ones marked, firewall events per rule, and your fixed checkpoints (`daily.paths` origin-reach limits, `daily.artifacts` known accounting artifacts).

## Deployment

The primary form factor is a single Go binary in a Docker container, running on **your own** VPS, home server or NAS — deliberately *not* on Cloudflare itself, so the watchdog has no blind spot when the platform it watches is the thing in trouble. The engine only needs outbound HTTPS and a local state file; a Cloudflare Workers (Cron Triggers) deployment adapter is on the roadmap as an alternative.

## Roadmap

- ~~v0.2~~ — daily digest (24 h comparison + fixed checkpoints) ✅
- ~~v0.3~~ — full intraday watch (new-face detection, escalation/recovery state machine, attribution queries) ✅
- ~~v0.4~~ — suggestion engine (block / challenge / rate-limit / cache candidates) + local SQLite archive ✅
- ~~v0.5~~ — one-click blocking (IP / CIDR / ASN / country / user-agent — block from an alert or the CLI, expiring blocks, guard rails, audit log) ✅
- **v0.6** — WAF rule audit (coverage gaps on sensitive paths, ordering/redundancy issues, per-rule hit stats, over-broad exemptions)
- **v0.7** — general action module (execute approved suggestions with a separate write token, pre-change backup, read-back verification)
- **v0.8** — more notification channels, multi-zone
- **v1.0** — calibration tooling against dashboard numbers, docs site

Full specification: [SPEC.md](SPEC.md) (Chinese).

## Limitations

- Cloudflare's GraphQL Analytics is sampled and has no referer dimension; very large sites will find attribution too coarse. FlareHound targets small-to-medium sites.
- What analytics expose depends on the plan. FlareHound probes each zone at startup and degrades instead of failing: on **Free**, there is no ASN breakdown (new-ASN detection and ASN suggestions are off) and no firewall events (block attempts show "n/a"); crawlers are verified with Cloudflare's own `verifiedBotCategory` instead.
- Analytics ingestion lag (~5–10 min) sets the detection floor. This is a watchdog, not a real-time shield — edge rules remain the shield.
- The local archive stores hourly aggregates, not raw request logs; it cannot reconstruct individual requests, and history starts accumulating only from the day you deploy.
- No AI sits in the detection path: findings are deterministic and reproducible from the same data. An optional bring-your-own-key AI explainer that narrates findings is on the long-term roadmap — it will never gate, suppress or act on an alert.

## License

MIT © 2026 playwjj
