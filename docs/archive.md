# Local archive & calibration

## Why an archive

Cloudflare keeps about 31 days of adaptive analytics (firewall events likewise, and not at all on Free), and raw logs are a metered add-on. FlareHound snapshots every check into a local SQLite file, building the long memory the platform does not keep. The archive holds **aggregates, never individual requests**.

## File and contents

- Path: `archive.file`, default `archive.db` in the data directory (next to `state_file`, so `data/archive.db` by default). One file; backing it up means copying it. SQLite in WAL mode, via a pure-Go driver.
- Disable it with `archive.disabled: true` — but `-backfill`, `block --for` (expiry times) and the [rule-change commands](rules.md) (backups and audit log) need it.

| Table | Holds | Kept |
|---|---|---|
| `snapshots` | One row per zone per window (`hour`, and `day` from the daily report): totals plus the full query set as JSON — cache-status split, top dynamic paths, firewall events per rule, and (from v1.14) the top 50 client IPs with their ASN, Cloudflare-verified bot addresses apart (from v1.14.1), and the top 50 IPs stopped at the edge | Hourly: `archive.hourly_retention_days` (default 400, min 30); daily: forever |
| `faces` | First and last time each UA / ASN appeared in any Top list, and its peak count | Forever |
| `alerts` | Every message-producing decision: window, decision, fingerprint, findings | Forever |
| `block_events` | Audit log of [blocking](blocking.md): block, unblock, expire | Forever |
| `rule_backups`, `rule_changes` | Snapshots and audit log of the [rule-change module](rules.md) | Forever |
| `calibration_days` | Per-day [calibration](#calibration) measurements | Forever |

Each intraday round writes the current window (with five extra queries for the breakdowns: cache status, dynamic paths, firewall events, client IPs, IPs stopped at the edge) and the baseline window — the baseline only if it is not archived yet, so a fuller copy is never overwritten. Old hourly snapshots are pruned each round. Archive read/write errors are logged and never stop the watch.

## What it is used for

- **Long baseline** — once there are ≥ 20 same-hour samples from the last 28 days, volume findings must cross their line against yesterday **and** the 4-week median ([Detection](detection.md#long-baseline)). The daily report shows progress until then.
- **Face history** — new faces in alerts are annotated "first seen in the archive" or "seen before: first / last / peak". Until the archive covers 7 days, first-seen claims are replaced by one line about the archive depth (on day one every face is new).
- **Zombie rules** and **block attempts** over periods longer than Cloudflare keeps.
- **Rule backups** for `flarehound rules restore`.

## Backfill

Fill the archive from Cloudflare's retained data instead of waiting four weeks:

```bash
flarehound -config config.json -backfill 28
```

- `N` is 1–30 days (Cloudflare keeps ~31).
- Windows already archived are skipped, so it is safe to re-run.
- Backfilled windows contain the core metrics and Top lists only.
- Pacing: about one query per second; each window costs `5 + number of Workers + number of path_rules` queries, so expect about an hour per zone for 28 days. The log prints the estimate and progress.

## Calibration

FlareHound reads Cloudflare's **adaptive** analytics (`httpRequestsAdaptiveGroups`), which are sampled and also count Worker subrequests and cache operations. The dashboard's totals (`httpRequests1dGroups`) do not. Expect FlareHound's numbers to be higher. All thresholds are in FlareHound's (adaptive) units — compare alerts with alerts, never with the dashboard.

```bash
flarehound calibrate --days 7          # all zones; read token only
flarehound calibrate --zone example.com
```

For each UTC day it compares:

| Measure | Dashboard side | FlareHound side |
|---|---|---|
| Requests | `requests` | adaptive `count` (with its average sample interval) |
| Edge cache hits | `cachedRequests` | requests with `cacheStatus = hit` |
| Edge 5xx | 5xx in `responseStatusMap` | `edgeResponseStatus` 500–599 |

The summary is the **median** of the daily ratios (robust to one odd day). Cache-hit ratios count only days with ≥ 100 dashboard hits, 5xx ratios only days with ≥ 50 dashboard 5xx. It also shows the sampling rate and translates `min_count` into dashboard units.

| Verdict | Request ratio | Meaning |
|---|---|---|
| FlareHound counts more | > 1.15 | Expected: subrequests and cache operations |
| FlareHound counts less | < 0.85 | Unusual: heavy sampling or ingestion lag; re-run later |
| Aligned | within ±15% | — |

When edge 5xx run more than 1.5× the dashboard, the output points to cache-operation artifacts (for example Cache API misses recorded as 504) and suggests listing them under [`daily.artifacts`](configuration.md#daily).

Measured days are stored in the archive and never queried twice; the summary covers the newest `max(--days, 7)` stored days. `--days` takes 1–365. The daily report calibrates the previous UTC day automatically and adds a one-line ratio.

!!! note "Measured on a live Free zone"
    Over 7 days FlareHound counted ≈ **1.29×** the dashboard's requests (1.23–1.35 per day), edge cache hits ≈ 1.09×, and edge 5xx ≈ **1.84×** — the 5xx excess being cache-operation artifacts. Sampling kept about 91% of requests.
