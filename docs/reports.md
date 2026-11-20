# Alerts, daily report & suggestions

Every message is plain text, conclusion first, in English or Chinese (`report.language`). Besides the text, each message carries structured fields (`kind`, `zone`, `decision`, window, fired `rules`) that the webhook and JSONL channels pass on — see [Channels](channels.md).

| `kind` | Sent when |
|---|---|
| `intraday` | The hourly watch decides `alert`, `changed`, `escalate` or `recovered` ([Detection](detection.md#alert-discipline)) |
| `daily` | Every day at `schedule.daily_report_at` |
| `audit` | The custom-rules ruleset changed and the re-audit found problems ([WAF audit](audit.md)) |

## How a message reads

Every message follows one order: **conclusion → evidence → details**. One sentence says what happened and whether to act, then the key numbers, then the technical details (or the console).

- A comparison is always *"value (what it was, change)"*: "137 (previous day 37, 3.7×)". Doubling or more reads "N×", under 1% "flat", from zero "new".
- Clients get names a person recognises: "Go program (Go-http-client/1.1)", "Chrome 131 · Windows", "crawler Googlebot"; a browser shell without a browser version is called out as "incomplete browser user agent (usually a script posing as a browser)".
- FlareHound's own status (plan limits, token permissions, local history, counting basis) is not news: the daily report shows it **when it changes**, and weekly otherwise. Failed queries (data gaps) are said every time.

Words used (earlier versions → now):

| Before | Now |
|---|---|
| line crossed | above normal / needs a look |
| baseline | normal level (same hour over 4 weeks, or the previous day) |
| dynamic | requests the origin has to handle (not cached) |
| zone requests | total requests |
| Top UA / Top ASN | main clients / main source networks |
| new face | new client / new source network |
| hypotheses, falsified if | likely causes, not this if |
| block candidates | IPs you could block |
| checkpoints | routine checks |
| bookkeeping background | Cloudflare's everyday 522/524 background |

## Intraday alert

```
FlareHound · example.com — something is off
⚠️ Needs a look: Worker web calls up, Worker web runs slower per call, More requests reach the origin and 2 more
Window 2026-11-17 08:00–09:00 (Asia/Shanghai)

▶ More requests reach the origin
Requests not served from cache (the origin or Worker has to build them): 70,000 (same hour yesterday 40,000, +75%).
→ Next: see "Paths that reach the origin" below for the pages that missed the cache.

▶ New source network: EXAMPLE-HOSTING-AS (AS207990)
45,000 requests; it was not among yesterday's top 25. It is a hosting / cloud network: real people rarely browse from there.
→ Next: unless it is your own service or a partner, consider a challenge or a block (see the suggestions below).

Traffic (compared with the same hour yesterday):
- total requests: 152,000 (same hour yesterday 100,000, +52%)
- requests the origin has to handle (not cached): 70,000 (same hour yesterday 40,000, +75%)
- origin errors (5xx): 5 (same hour yesterday 5, flat); 502 ×5

Where it comes from:
- paths that reach the origin most: /rank 35,000 (yesterday 20,000)
- AS207990 mostly fetches: /rank 35,000

Likely causes:
- [likely] Crawler/bot surge: new source AS207990 carries ~87% of the excess.
  Not this if: its path mix matches normal visitors and it comes from residential/mobile networks …

Suggestions (read-only — FlareHound never applies them; do it in the Cloudflare dashboard):
1. Block AS207990 (EXAMPLE-HOSTING-AS, hosting network)
   ...
```

The parts, in order:

1. **Lines 1–2** — the zone and the kind of message, then *what needs a look* in plain titles (most consequential first: outages and errors, then cost, then volume, then new clients).
2. **One block per finding** — a title, the number with what it was (*"137 (previous day 37, 3.7×)"*), what it most likely means (errors with flat traffic point at the origin itself; volume with flat origin work was absorbed by the cache …) and **→ Next:** one concrete step. Up to five; more are listed one line each.
3. **Traffic** — total, requests that reach the origin, origin errors (5xx, with their share of origin answers and status split), Cloudflare unable to reach the origin (52x, with the 522/524 judgement), origin response time (P95), each Worker; plus the 4-week normal level when it is active.
4. **Where it comes from** — collected only when a message is going out. A failed query never blocks the alert.
5. **Likely causes** — each with how likely it is and what would rule it out. With none supported, the message says it reports numbers only.
6. **IPs you could block** and **suggestions** — see below. Recovery messages are one line.

Email gets the same report as HTML with charts, and Telegram, Discord and WeCom get the charts as images — see [charts and HTML](channels.md#charts-and-html-reportvisuals-default-on).

### Severity: is it loud, or does it hurt?

A surge the cache absorbs — total requests or Worker calls up, new clients, but **requests that reach the origin (`dynamic`) up less than 15%** and nothing on the origin, CPU, errors, drops or paths above normal — is reported as its own verdict, **minor** (🟡): *"The extra traffic is absorbed by the cache: requests the origin handles +1.0%, CPU and origin errors normal — no pressure on the origin or the Worker. Watch it, nothing to do."* A Worker CPU median rise that P99 and the call count explain as a **change in the request mix** (and nothing else expensive) is also minor: *"minor: Worker CPU moved because the request mix changed"*. Anything expensive or broken makes it **high**. The JSONL record carries `severity: "low" | "high"`.

### Dashboard terms and network labels

Once [calibration](archive.md#calibration) has data, every request count in a finding carries its dashboard equivalent — *"(about 9,080 as the Cloudflare dashboard counts)"* — because people think in dashboard numbers. A new ASN is labelled with its registered name and network type — *"AS45102 [ALIBABA-CN-NET, hosting/cloud network]"* — so nobody has to look it up before deciding (name lookup needs the `clientASNDescription` dimension; the built-in table works without it).

### Expensive vs. cheap

Traffic is split by `cacheStatus`: `hit`, `stale`, `updating` and `revalidated` are **cheap**; everything else (`dynamic`, `miss`, `bypass`, `expired`, unknown values) is **expensive**. Real rendering (`dynamic`) is shown first and separately from other cache misses — it is the number an on-call human watches.

### Hypotheses

Produced by fixed rules, for example:

- A new face carrying ≥ 80% of the excess → high confidence; ≥ 50% → medium.
- ≥ 70% of the excess on cheap traffic → "cheap volume, small real cost".
- Dynamic up while total is flat → cacheability dropped.
- CPU up while invocations are flat → deployment or slow path.
- Origin 5xx, with the per-path distribution; ≥ 80% on one path → a defect in one route rather than an origin failure.
- Anything else → no concentrated driver, not enough evidence.

### Block candidates

- Shares are of the **excess** (current − baseline). No excess, no candidates: a CPU, 5xx or collapse anomaly with flat traffic never proposes IP blocks.
- A single IP carrying ≥ 5% of the excess is listed with a one-click command (`flarehound block ip … --for 24h`).
- Every IP line — block candidates, top client IPs, the daily report's most-blocked IPs and FlareHound blocks — carries its [IP location](configuration.md#geoip) when a country library is loaded: `106.201.104.211 [IN · India]`, or with `report.language: zh` `106.201.104.211 [印度 (IN)]`. It is the registered/routed country, not the operator's, and it never changes what is reported.
- If the largest blockable IP carries < 1%, sources are **dispersed**: the message says per-IP blocking will not help and points to ASN or path-level action.
- Cloudflare's own ranges (typically a Worker calling your site), private / reserved ranges and `blocking.never_block` entries are listed separately as "concentrated but not blockable", with the reason.
- UAs that claim to be a known crawler and fail verification are named as **impostors**.

## Suggestions

Suggestions are read-only advice; each comes with evidence, expected gain, impact, rollback and — where FlareHound can apply it — a one-click command for the [blocking](blocking.md) or [rule-change](rules.md) module. At most 6 per message.

| Kind | Trigger | Advice | One-click command |
|---|---|---|---|
| Block ASN | ASN explains ≥ 20% of the excess **and** is a hosting/cloud network | Block `(ip.geoip.asnum in {N}) and not cf.client.bot` | `flarehound block asn N --action block --for 24h` |
| Challenge ASN | Same, but a residential/backbone or unknown network | Managed Challenge, explicitly *not* block | `flarehound block asn N --for 24h` |
| Challenge path | A sensitive path's line crossed, or it explains ≥ 30% of the dynamic excess | Managed Challenge on that path | `flarehound rules add --action managed_challenge …` |
| Rate limit | One path explains ≥ 50% of the dynamic excess, sources dispersed, not already covered by a challenge suggestion | Per IP, 20 requests / 10 s, Managed Challenge | `flarehound ratelimit add --path … --requests 20 --period 10` |
| Cache | A static-asset path (js, css, images, fonts, media, pdf, xml, wasm …; not json) among the top dynamic paths with ≥ `min_count` requests | Edge cache rule, TTL 1 day (1 year for content-hashed file names) | `flarehound cache add --path … --ttl 1d` |
| Cost hint | CPU up while invocations are flat | Check the Worker's deployments and slow paths | — |

Evidence gates:

- Block, challenge and rate-limit suggestions need at least one medium- or high-confidence hypothesis.
- When ≥ 70% of the excess is cheap edge traffic, no blocking-type suggestion is made.
- Cache and cost suggestions are structural and not gated.
- Sensitive paths are all patterns in `path_rules` and `daily.paths`.
- Network type comes from a built-in table of major cloud / hosting and broadband / backbone ASNs, then from keywords in the ASN's registered name where the plan provides it; otherwise "unknown". Cloudflare's own ASNs and `blocking.never_block_asns` are never suggested.

Path patterns become expressions as follows: `/x` → `http.request.uri.path eq "/x"`; `/x*` → `starts_with(http.request.uri.path, "/x")`; other patterns containing `*` → `wildcard`.

## Daily report

Sent every day (it is a scheduled report, not an alert). The second line is "✅ All normal" or "⚠️ Needs a look: …", followed by one block per finding (title, numbers, meaning, next step), as in the alert.

- Last 24 h vs. the previous day: the same signals as the hourly watch (without the state machine), the cache split, the paths that reach the origin most.
- Main source networks and main clients with new ones marked `[new]`; verified crawlers and fake crawlers.
- **Routine checks:**
    - firewall events by rule (with rule names) and the IPs most often blocked or challenged — or "unavailable" on plans without the dataset, never 0;
    - each FlareHound block with its attempts in the window, start and expiry — lift a block when the attempts stop, not when it gets quiet;
    - blocks made in the window with their before/after verdict and, when confirmed after a [simulation](simulator.md), its predicted net new against what the rule stopped;
    - the **rule simulator's record** over 30 days: blocks that came with a prediction, how many were measured, and the typical and widest deviation of actual from predicted (per hour) — "Rule simulator accuracy, last 30 days: 4 block(s) came with a prediction of how much they would newly stop, 3 measured — actual vs predicted per hour: typically −11%, at most +85% (AS45102)";
    - `daily.paths`: origin reach per path vs. its `max` (✓ / ⚠);
    - `daily.artifacts`: known accounting artifacts, counted separately from visitor errors.
- Suggestions (no rate-limit advice: the daily report has no per-IP data).
- WAF audit summary: one line when clean, details only for what needs attention.
- An intraday anomaly still open, with its start (ahead of the findings).
- **System status** (when it changes, and weekly): no ASN data on the plan, firewall events unreadable, local history and how far the 4-week normal level has filled (with a `flarehound -backfill 28` hint), the [counting basis](archive.md#calibration), the purpose-table version. What was last shown is kept in `*-status.json` next to the state file.
- Data gaps: any query that failed is named instead of silently reported as zero (every time).

Run it on demand with `flarehound -daily` (add `-dry-run` to print instead of send).
