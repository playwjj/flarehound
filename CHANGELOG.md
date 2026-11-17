# Changelog

All notable changes to FlareHound. Versions follow [semantic versioning](https://semver.org/); every `v*` tag publishes multi-arch Docker images (`linux/amd64`, `linux/arm64`).

## v1.1.0 — 2026-11-17

From the first days on a production Pro zone.

- **Heartbeat / dead-man switch**: every round writes `data/heartbeat`, a `kind: "heartbeat"` JSONL record and, with `notify.heartbeat_url_env`, pings a healthchecks.io-style URL (`/fail` on zone errors). `flarehound health` + Docker `HEALTHCHECK`; the admin container checks its own heartbeat.
- **`flarehound doctor`**: configuration, a per-zone capability matrix (watch, audit, calibration, blocking, rule changes, cache rules) naming each missing permission, plan capabilities and firewall-event retention, last/next run, heartbeat, archive span, outbox.
- **Edge-absorbed floods** are their own low-severity verdict (real rendering < +15%, nothing expensive crossed), shown first; JSONL carries `severity`.
- Findings carry **dashboard equivalents** from calibration, and new ASNs their **name and network type**.
- WAF audit: coverage reported at **block and challenge level**; the probe is a non-verified client (`not cf.client.bot` rules now count as full coverage); rules that apply to every path alike are no longer "partial coverage" of a path; skip-rule bypasses grouped per skip rule.
- Fix: firewall-event windows aligned to the hour inside the retention edge; if the oldest day is still rejected, the newer days are kept.
- Fix: the first alert after a start labels firewall events with rule names.
- JSONL file mode 0644. Docs: IP Access Rule permissions differ by account (optional; FlareHound degrades).

## v1.0.0 — 2026-11-17

First stable release.

- **Calibration** against the Cloudflare dashboard: `flarehound calibrate [--days 7]` compares FlareHound's adaptive counts with the dashboard's (`httpRequests1dGroups`) per UTC day — requests, edge cache hits, edge 5xx, sampling rate — and translates `min_count` into dashboard units. The daily report calibrates the previous UTC day automatically and carries a one-line ratio. On a live Free zone FlareHound counted ≈ 1.29× the dashboard; edge 5xx ≈ 1.84× (cache-operation artifacts, now pointed out with a hint to `daily.artifacts`).
- **Documentation site** (MkDocs Material, published to GitHub Pages): quick start, permissions, full configuration reference, detection, reports, channels, archive and calibration, blocking, rule changes, WAF audit, CLI, limitations, troubleshooting, Chinese overview.
- `CHANGELOG.md`.

## v0.8.0 — 2026-11-17

- Notification channels: Slack, Discord, WeCom (企业微信), Feishu/Lark (飞书, optional signing secret) and SMTP email (STARTTLS / implicit TLS; never credentials over plaintext). Per-service size limits with numbered splitting on character boundaries; bot errors returned inside HTTP 200 count as failures.
- Parallel multi-zone checks (`schedule.max_parallel_zones`, default 4), race-tested.
- No block candidates without excess traffic; origin 5xx attributed by path, single-route concentration reported as an application bug.
- Permission texts prefer **Zone → WAF** (covers custom rules and IP Access Rules); *Firewall Services* is the legacy name.

## v0.7.1 — 2026-11-17

- Fix: `clientAsn` is a String in the GraphQL schema — quote it in filters and accept string dimension values (ASN-filtered queries silently degraded before).
- Restore verified live: rules keep their IDs (matched by `ref`); warning corrected.

## v0.7.0 — 2026-11-17

- General execution module: `rules list/add/edit/delete/move/backups/restore/log`, `ratelimit add`, `cache add`. Every change shown in full and confirmed (no `--yes`), backed up first (archive + JSON file), syntax-checked locally, read back and logged; any backup can be restored.

## v0.6.0 — 2026-11-17

- WAF rule audit: Cloudflare rules-language parser with three-valued evaluation; coverage of sensitive paths, rules shadowed or bypassed by earlier rules, forgeable exemptions, hits and zombie rules, quota and merge groups. `flarehound audit`, daily report section, re-audit on ruleset changes, firewall events labelled with rule descriptions.

## v0.5.2 — 2026-11-17

- Block candidates pass the guard rails; Cloudflare-owned IPs are explained as Worker egress.
- Cost split shows real rendering (`dynamic`) separately; empty user agent labelled; impostor crawlers named; first-seen suppressed while the archive is young; `rule_names`.
- JSONL file channel and structured messages; daily top blocked/challenged IPs; `path_rules[].dynamic_only`; read token narrowed to Zone → Analytics: Read.

## v0.5.1 — 2026-11-17

- Fixes from the first live run on a Free zone: capability probing (no `clientAsn`, no firewall events on Free), crawler verification via `verifiedBotCategory`, blocking degrades on partial write-token permissions.

## v0.5.0 — 2026-11-17

- One-click blocking of IPs/CIDRs, ASNs, countries and user agents in FlareHound-owned rules and lists, with guard rails, strong confirmation for wide blocks, read-back verification, TTLs (`enforce`) and an audit log.

## v0.4.0 — 2026-11-17

- Suggestion engine (block / challenge / rate-limit / cache / Worker cost) with evidence, gain, impact, rollback and paste-ready expressions.
- Local SQLite archive: hourly and daily snapshots, 4-week same-hour baseline, face history, alert history, `-backfill`.
- v0.2 daily report and v0.3 full intraday watch (attribution, hypotheses, verified crawlers, settle re-read, state machine).

## v0.1.0 — 2026-11-17

- Skeleton: configuration, GraphQL client, detection engine with the 2026-11-17 incident thresholds, state machine, webhook/Telegram notification, Docker packaging, SPEC.
