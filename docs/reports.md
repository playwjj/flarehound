# Alerts, daily report & suggestions

Every message is plain text, conclusion first, in English or Chinese (`report.language`). Besides the text, each message carries structured fields (`kind`, `zone`, `decision`, window, fired `rules`) that the webhook and JSONL channels pass on — see [Channels](channels.md).

| `kind` | Sent when |
|---|---|
| `intraday` | The hourly watch decides `alert`, `changed`, `escalate` or `recovered` ([Detection](detection.md#alert-discipline)) |
| `daily` | Every day at `schedule.daily_report_at` |
| `audit` | The custom-rules ruleset changed and the re-audit found problems ([WAF audit](audit.md)) |

## Intraday alert

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

Suggestions (read-only — FlareHound never applies them; do it in the Cloudflare dashboard):
1. Block AS207990 (EXAMPLE-HOSTING-AS, hosting network)
   where: Security → WAF → Custom rules, action Block
   expression: (ip.geoip.asnum in {207990}) and not cf.client.bot
   ...
```

The parts, in order:

1. **Headline** — which lines were crossed and by how much (up to four; collapse, 5xx, expensive, total and new faces first).
2. **Two-window comparison** — total, Worker invocations and CPU P50 / P99, dynamic, origin 5xx (with its share of origin answers and the 502/503/504 split), origin unreachable (52x, when any, with its status split and — against a 522/524 background — a one-line judgement: bookkeeping, or a departure and why), origin latency P95 (first byte / full response); plus the long baseline when it is active.
3. **Attribution** — collected only when a message is going out (quiet rounds cost no extra queries). A failed attribution query never blocks the alert.
4. **Hypotheses** — each with confidence and a falsifier. With no supported hypothesis the message says it reports numbers only.
5. **Block candidates** — see below.
6. **Suggestions** — see below. Recovery messages carry no suggestions.

Email gets the same report as HTML with charts, and Telegram, Discord and WeCom get the charts as images — see [charts and HTML](channels.md#charts-and-html-reportvisuals-default-on).

### Severity: is it loud, or does it hurt?

A flood that the edge absorbs — zone requests or Worker calls up, new faces, but **real rendering (`dynamic`) up less than 15%** and no dynamic, CPU, origin 5xx, origin slow/unreachable, collapse or path line crossed — is reported as its own verdict at **low severity**: *"edge-absorbed flood: the extra traffic is absorbed at the edge, real rendering +1.0%, CPU and origin errors unchanged — watch it, no action needed."* A Worker CPU P50 rise that P99 and the call count explain as a **mix change** (and nothing else expensive) is also low severity: *"low severity: Worker CPU mix change"*. Anything expensive or broken makes it **high**. The JSONL record carries `severity: "low" | "high"`.

### Dashboard terms and network labels

Once [calibration](archive.md#calibration) has data, every count in "lines crossed" carries its dashboard equivalent — *"new user agent … 18,521 requests (≈ 9,080 in dashboard terms)"* — because people think in dashboard numbers. A new ASN is labelled with its registered name and network type — *"AS45102 [ALIBABA-CN-NET, hosting/cloud network]"* — so nobody has to look it up before deciding (name lookup needs the `clientASNDescription` dimension; the built-in table works without it).

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

Sent every day (it is a scheduled report, not an alert). The first line is "All clear" or the conclusion.

- Last 24 h vs. the 24 h before: the same lines as the hourly watch (without the state machine), cost split, top dynamic paths.
- Top ASNs and user agents with new ones marked `[new]`; verified crawlers and impostors.
- **Checkpoints:**
    - firewall events by rule (with rule names) and the IPs most often blocked or challenged — or "unavailable" on plans without the dataset, never 0;
    - each FlareHound block with its attempts in the window, start and expiry — lift a block when the attempts stop, not when it gets quiet;
    - blocks made in the window with their before/after verdict and, when confirmed after a [simulation](simulator.md), its predicted net new against what the rule stopped;
    - the **rule simulator's record** over 30 days: blocks confirmed with a net-new prediction, how many were measured, and the median and widest deviation of actual from predicted (per hour) — "Rule simulator, last 30 days: 4 block(s) confirmed with a net-new prediction, 3 measured — actual vs predicted per hour: median −11%, widest +85% (AS45102)";
    - `daily.paths`: origin reach per path vs. its `max` (✓ / ⚠);
    - `daily.artifacts`: known accounting artifacts, counted separately from visitor errors.
- Suggestions (no rate-limit advice: the daily report has no per-IP data).
- WAF audit summary: one line when clean, details only for what needs attention.
- An intraday anomaly still open, with its start and signals.
- Archive status and long-baseline readiness (with a `-backfill 28` hint while it fills).
- A one-line [calibration](archive.md#calibration) ratio.
- Data gaps: any query that failed is named instead of silently reported as zero.

Run it on demand with `flarehound -daily` (add `-dry-run` to print instead of send).
