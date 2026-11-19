# Detection

FlareHound's detection is deterministic: the same two windows always produce the same findings. There is no AI in the detection path.

## Windows and schedule

- **Intraday watch** — `schedule.intraday_offset` (default 7 min) after every interval boundary, FlareHound compares the **last full clock window** (default one hour) with **the same window yesterday**. The state file records the last evaluated window, so a restart never evaluates the same window twice. On start-up it catches up on the newest settled window right away.
- **Daily report** — at `schedule.daily_report_at` (default 08:00, in `schedule.timezone`): the last 24 hours vs. the 24 hours before. See [Reports](reports.md#daily-report).
- **Several zones** are checked in parallel, at most `schedule.max_parallel_zones` (default 4) at a time, each with its own state file.

## What is measured

Each window, for each zone (Cloudflare GraphQL Analytics, `httpRequestsAdaptiveGroups` and `workersInvocationsAdaptive`):

1. Zone requests (total).
2. Requests with `cacheStatus = "dynamic"` — the expensive, uncached part.
3. Origin 5xx (`originResponseStatus` 500–599), split by status (502 / 503 / 504 …) and as a share of the requests the origin answered.
4. **Origin unreachable** — the edge's own 52x answers (`edgeResponseStatus` 520–526 and 530): Cloudflare could not reach the origin at all (521 refused, 522/524 timed out, 523 no route, 525/526 TLS). The origin answered nothing, so these never show up as origin 5xx.
5. **Origin latency** — P95 time to first byte (`originResponseHeaderReceiveDurationMs`: the application computing) and of the full response (`originResponseDurationMs`: plus transfer), with TCP/TLS connect P95s as detail. Read over the requests the origin actually answered (`originResponseStatus > 0`); cache hits would pull the quantiles to 0. Available on every plan, Free included; where the API does not answer, latency is "not measured" and the round goes on.
6. Per configured Worker: invocations and CPU P50.
7. Top user agents and Top ASNs — Top 10 for the current window, Top 25 for the baseline ("old faces").
8. Per `path_rules` entry: requests matching the path (optionally `dynamic` only).

## Alert lines

Any line crossed puts the zone into an anomaly. Defaults (all configurable under [`thresholds`](configuration.md#thresholds)):

| Rule | Fires when | Default |
|---|---|---|
| `total_up` | Zone requests rise ≥ `total_up_pct` and the current window ≥ `min_count` | +35% |
| `dynamic_up` | Dynamic responses rise ≥ `dynamic_up_pct`, current ≥ `min_count` | +50% |
| `worker_calls_up` | A Worker's invocations rise ≥ `worker_calls_up_pct`, current ≥ `min_count` | +35% |
| `cpu_p50_up` | A Worker's CPU P50 rises ≥ `cpu_p50_up_pct`; both windows' invocations ≥ `min_count` | +25% |
| `origin_5xx` | Origin 5xx > `origin_5xx_min` **and** ≥ `origin_5xx_multiplier` × baseline | 3× and > 50 |
| `origin_unreachable` | Edge 52x ≥ `unreachable_min` **and** ≥ 2× baseline (normally 0) | ≥ 10 |
| `origin_slow` | The origin's first-byte P95 rises ≥ `origin_slow_up_pct` **and** reaches `origin_slow_min_ms`; both windows ≥ 100 origin-answered requests. Reported as `ttfb` — or as `total` when only the full response slowed (transfer: large bodies, bandwidth) | +100% and ≥ 1 s |
| `collapse_total` / `collapse_worker` | Requests / invocations drop ≥ `collapse_down_pct`, baseline ≥ `min_count` | −50% |
| `new_face_ua` / `new_face_asn` | A UA / ASN in the current Top 10, absent from the baseline Top 25, with more than `new_face_min_count` requests | > 5,000 |
| `path_up` | A `path_rules` path rises ≥ its `up_pct`, current ≥ its `min_count` | +100%, ≥ 20 |

### Origin view: Worker sites and VPS sites

The same flood costs a Worker site money (the platform absorbs it; the bill comes later) and a site on one VPS behind the proxy its availability (PHP workers fill up, the site goes down). For the VPS the earliest symptom is a slower origin — hours before the first 5xx — and 52x means it is already down. Both lines are high severity; their hypotheses separate *slower under more uncached load* (dynamic or total up, new faces) from *slower with load flat* (application, database, the machine itself), and *first byte* from *transfer*.

FlareHound only sees the edge: database locks, a full disk or memory pressure on the VPS are visible only as their effect on these numbers. Adaptive data is sampled — fit for trends and alerts, not SLA accounting.

`min_count` (default 1,000) exists because on a small site 10 → 40 requests is +300%; without a floor, quiet alerting is impossible.

### Collapse needs settled data

Fresh windows are under-counted while analytics are still ingesting. When a round shows a collapse, FlareHound waits `schedule.settle_delay` (default 3 min) and re-reads the window. If the count grew by more than 2%, the data was still arriving: the collapse is withheld this round and noted as "data not settled".

### Long baseline

Once the [archive](archive.md) holds at least 20 same-hour samples from the last 28 days, a volume finding (requests, dynamic, 5xx, Worker, CPU, collapse, path) must cross its line against yesterday **and** against the per-metric median of those samples. One odd yesterday no longer pages you. New-face findings are not subject to this check. Alerts show the long-baseline values and sample count.

## New faces and crawler verification

Legitimate crawlers change their UA version strings and look "new". A new UA that claims to be a known crawler is verified before it is excluded:

| Crawler | UA markers include | Own ASNs |
|---|---|---|
| Googlebot | `googlebot`, `adsbot-google`, `mediapartners-google`, … | 15169 |
| Bingbot | `bingbot`, `adidxbot`, `bingpreview` | 8075 |
| Applebot | `applebot` | 714, 6185 |
| YandexBot | `yandexbot`, `yandex.com/bots` | 13238, 208722 |
| Baiduspider | `baiduspider` | 55967, 38365 |

FlareHound prefers Cloudflare's own `verifiedBotCategory`; where that is unavailable it falls back to the crawler's ASNs. The claim is accepted when **≥ 90%** of the UA's requests pass. A UA that fails with data to judge on is reported as an **impostor** — a disguised scraper. If neither method is available, nothing is excluded.

Register your own monitors and services under [`known_faces`](configuration.md#known_faces); they never count as new faces.

## Alert discipline

The state machine (persisted in `state_file`) turns findings into at most one message per round:

| Decision | When |
|---|---|
| `alert` | First finding: an anomaly episode starts. |
| `changed` | During the episode, a signal appears that the episode has not shown before. |
| `escalate` | A reported signal grows another `escalation_pct` (default 25%) past its reported peak. Collapses never escalate — recovering numbers are not worse. |
| `recovered` | `recovery_clean_rounds` (default 2) consecutive rounds without any finding. One short line; the episode ends. |

A signal is the rule plus its subject (Worker, path rule, ASN). All new-face UAs share **one** signal, because crawlers rotate UA strings (three batches in one day in the field); ASNs are stable, so each new ASN is a new signal. A signal dipping below its line and crossing again within the same episode does not re-alert.

## Plan capabilities

On first use per zone, FlareHound probes which dimensions and datasets the plan exposes and never queries unavailable fields. Missing pieces are logged as `not available on this plan, degraded: …`:

- **No `clientAsn`** (Free): no ASN Top lists, new-ASN detection off, no ASN suggestions; the daily report says so.
- **No `clientASNDescription`** (Free): network type comes from the built-in table only.
- **No firewall events dataset** (Free): firewall events and block attempts show "n/a", never 0.
- If the probe itself fails, FlareHound assumes everything is available and probes again next round.

See [Limitations](limitations.md) for what this means in practice.
