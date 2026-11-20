# Limitations

FlareHound states its limits up front rather than letting you discover them.

## Data

- **Sampled analytics.** Cloudflare's adaptive GraphQL analytics are sampled and extrapolated. On small sites fine-grained breakdowns can be unstable, and a low-volume path may return 0 rows — zero does not mean absent. Very large sites will find attribution too coarse; FlareHound targets small-to-medium sites.
- **Different units from the dashboard.** Adaptive counts include Worker subrequests and cache operations. On a live Free zone FlareHound measured ≈ 1.29× the dashboard's request count and ≈ 1.84× its edge 5xx (cache-operation artifacts). Thresholds are in FlareHound's units; see [Calibration](archive.md#calibration).
- **Ingestion lag** (about 5–10 minutes) sets the detection floor. This is a watchdog, not a real-time shield — edge rules remain the shield.
- **No referring-page dimension.** At most the referer's host is available (paid plans), so traffic cannot be split by referring page and "forged referer bypass" cannot be detected from analytics.
- **Worker CPU** is available only as quantiles (FlareHound uses P50), not as a total; any cost reading is an estimate.
- **Retention.** Cloudflare keeps about 31 days. `-backfill` can recover at most the last 30 days; anything older cannot be rebuilt. The archive holds hourly aggregates, never individual requests.
- **Database files level off, older ones never shrink.** Pruned rows free pages that new rows reuse. Only `archive.db` / `console.db` files created by v1.18 or later give space back to the disk after a large prune (for example after lowering `archive.hourly_retention_days`); files from earlier versions are not rebuilt and keep their size. See [disk space](archive.md#disk-space).

## Plans

What analytics expose depends on the plan. FlareHound probes each zone and degrades instead of failing. Verified on a live **Free** zone:

| Capability | Free | Effect when missing |
|---|---|---|
| `clientAsn` | not available | No ASN Top lists, no new-ASN detection, no ASN suggestions; the daily report says so |
| `clientASNDescription` | not available | Network type from the built-in table only |
| Firewall events dataset | not available | Firewall events, block attempts, audit hit statistics and `--observe` show "n/a" — never 0 |
| `verifiedBotCategory` | available | Used for crawler verification |
| Host and country dimensions | available | — |

Rule quotas also differ by plan (custom rules Free 5 / Pro 20 / Business 100 / Enterprise 1,000; rate-limit rules 1 / 2 / 5 / 100), and on Free the rate-limit period and mitigation timeout must be 10 seconds.

## Detection

- **Hard thresholds.** Slow growth (+5% a day) and attacks kept just under the line stay invisible; a legitimate surge (a launch, a viral post) looks the same as an attack in the numbers.
- **Baseline problems.** If yesterday itself was abnormal, the comparison is distorted. The 4-week median baseline (once the archive has enough samples) reduces this, but a long-lasting anomaly can still become the new normal.
- **No semantics.** Rules cannot know whether a new ASN is a crawler fleet or your own new service. Register known sources under `known_faces`.
- **Per-range shares** are not measured when blocking (ranges cannot be filtered in analytics); FlareHound says so in the plan. Country blocks are measured by the review's [simulation](simulator.md) — how much traffic, never how much of it is human.
- **IP location is a library's reading, not a fact.** It is the registered/routed country of an address — a residential proxy shows its exit, a data-centre address its data centre — and libraries disagree at the edges (DB-IP lite places Google's IPv6 resolver `2001:4860:4860::8888` in CA, GeoLite2 in US). There is deliberately no per-country traffic view built from it: countries inferred from the top IPs would be a heavily biased sample.
- No AI in the detection path: findings are deterministic and reproducible from the same data.

## Rule simulator

See [Rule simulator](simulator.md). Its limits, before its features:

- **Sampled approximation, not a replay.** There is no replay API; the expression is translated into filters over sampled, aggregated analytics. Sampling is the precision limit — there is no Logpush and no per-request log behind it.
- **The referer only to its host** (paid plans). A comparison on the full referer ("exactly the home page") is widened to its host: the report is labelled *upper bound* and names the sub-expression. Under a negation it is not evaluable.
- **Free zones** have no ASN dimension and no firewall events: ASN expressions are not evaluable there, and net new is not available. The report says so; it does not fill the gap from another source.
- **Net new is a joined estimate.** Matches come from the HTTP requests dataset, "already stopped" and "skipped ahead" from the firewall events — two datasets, sampled differently. The rule's position needs Zone → WAF: Read on the read token; without it net new is counted against the whole rule set. A skip rule ahead that logs nothing and cannot be translated makes net new an upper bound.
- **Challenge pass rates are a biased sample.** Only requests that met a challenge are in the firewall events: the range is a reference, not a prediction.
- **`$lists`** are expanded only for IP and ASN lists the read token can read (Account → Account Filter Lists: Read), up to 1,000 single values; managed `$cf.…` lists, lists with ranges and hostname lists are not evaluable.
- **Not evaluable, only bounded:** headers, cookies, bodies, regular expressions, wildcards, threat and bot scores, rates, functions other than `starts_with` / `ends_with`, unexpandable `$list` references and IP ranges. A term like that is named and bounded (upper: matches, lower: does not); the counts become upper bounds, with a lower bound for the matches. When nothing evaluable narrows the expression (the upper bound is the whole zone), it gets no numbers at all.

## Scope

- Cloudflare only. Origin internals (processes, databases) are out of scope.
- One process per deployment; runs on your own machine. A Cloudflare Workers deployment is not provided.
