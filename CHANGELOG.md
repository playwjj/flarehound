# Changelog

All notable changes to FlareHound. Versions follow [semantic versioning](https://semver.org/); every `v*` tag publishes multi-arch Docker images (`linux/amd64`, `linux/arm64`).

## v1.10.1 — 2026-11-18

- Console settings: space between the tab bar and the first card; a channel's checkbox, name and status tags sit on one line again.

## v1.10.0 — 2026-11-18

- **Snapshots of the WAF audit and the WAF rules.** Freeze the audit (with "How to fix") or the rule list (with plain-words explanations) into a revocable link for a site team — from the cached data, without forms or actions.
- **Who may create snapshots is explicit**: `console.snapshots` = `admins` (default), `everyone` or `off`.
- **Blocks get a verdict.** Every before/after now ends with one sentence — "requests 45,000 → 900 (−98 %), practically gone; the rule stopped 850 attempts", "still coming, but 95 % answered 403", or "no clear effect — check that the rule matches". The daily report lists the blocks made in its window with that verdict.
- **Faces already handled by a rule are marked.** New faces, movers and the drill-down tag user agents and ASNs that an enabled custom rule acts on ("blocked by rule #3"; "rule #N may act on it" when it depends on the path), and new-face alerts say "already blocked by rule #3: this volume is blocked requests". Judged by evaluating the zone's rules; only rules that look at the face's dimension count. ASN signal keys are spelled one way (`AS150436`); state files with the bare-number spelling are merged on load.
- **TOTP sign-in friendlier, not weaker.** Only failed attempts count against the per-address limit (successful sign-ins no longer do); wrong codes no longer lock the account — five end the pending sign-in (password again), and an account-wide limit of 20 wrong codes an hour stays. A code from the previous or next 30-second step was and is accepted (now covered by a test).
- **Cross-zone home.** With several zones, `/` lists them all, most in need of attention first: an open alert episode, origin 5xx over its line, other lines over, new faces, recent alerts, stale data — from the archive and the watch's state, no Cloudflare query.

## v1.9.0 — 2026-11-18

- **Settings in the console** (admins; review → TOTP → audit first): notification channels (on/off, non-secret parameters, the *names* of the environment variables holding their secrets), alert lines, known faces and network names. Kept in `settings.json` next to the state file, on top of `config.json` (unchanged, may stay read-only); every change keeps the previous version and can be restored, back to "config.json alone". No secret is ever stored.
- **The watch applies changes without a restart** (before its next round) and reports back: the settings version it runs, a newer one accepted or **rejected with the reason** (e.g. a variable that is empty in its process) — a rejected change never stops alerts, the previous settings stay in force. It also reports, per channel, which referenced variables are set in its process (never values).
- **Test notifications are sent by the watch**, with its own environment: per channel, "delivered" or the exact error ("SLACK_HOOK_TYPO is empty in the watch process") within seconds.
- **Alert lines with a preview**: before saving, the last 7 days of the archive are replayed with the new lines the way the watch evaluates (vs the day before, cross-checked with the 28-day median) — hours over a line and episodes, now vs after, and which hours change.
- **Mark as known** in one click next to user agents and ASNs on the new-faces, movers and drill-down pages.
- **Network names.** The watch records the registered names of each hour's top networks; the console shows every ASN as "AS207990 · HostRoyale · hosting" (network type from the registered name). Operators can give short names (`asn_names` in config.json, or "name it" next to any ASN in the console): used in the console *and* in notifications, falling back to the registered name.
- The console and `doctor` no longer fail when a notification variable is missing in their own environment (the console sends no alerts; `doctor` now reports it per channel). `console --listen`, `doctor` settings section.

## v1.8.0 — 2026-11-18

- **Console language switch (English / 中文).** A button in the header (on the sign-in page too) switches the console's language for this browser; signed-in accounts keep the choice and get it on any device. Order: this browser's choice, then the account's, then `report.language`. Rule explanations, audit fixes and recipe texts follow the viewer's language (cached rule lists are shared and explained per viewer); snapshots are rendered in their creator's language, password-reset mails in the account's. Notifications keep following `report.language`. Existing account databases gain a `lang` column automatically.

## v1.7.2 — 2026-11-18

- **TOTP set-up by QR code.** The account page shows the authenticator key as a QR code (inline SVG, always dark on light) next to the key for manual entry. Generated with `rsc.io/qr` (pure Go, BSD); verified by decoding it in a browser.
- **Password reset by e-mail.** With `notify.email` (SMTP) and `console.base_url` configured, the sign-in page offers "Forgot your password?": a single-use link valid for 30 minutes is mailed to the address on the account. The page answers the same whether or not the account exists, and the mail is sent in the background; at most one mail per account every 10 minutes and ten requests a minute per IP. A reset ends every session of the account, lifts a lockout and voids its other links; two-factor sign-in still applies. Requests, mails and resets are audited. `doctor` says whether it is available.

## v1.7.1 — 2026-11-18

- **Faster on slow links.** The drill-down runs its queries four at a time (about 20 s → 3.5 s on the test zone over a slow connection; cached afterwards). The WAF rules and WAF audit pages are kept warm in the background (rules re-read every 10 minutes, the audit when 30 minutes old) and open immediately; any rule change made in the console refreshes both. The rules page shows when it was read, with a refresh link.
- **Plan-aware.** On plans whose analytics have no ASN dimension (Free), the movers and new-faces pages say so instead of showing an empty list. Recipes that would exceed the plan's rule quota say so in the catalogue and on the form (no form to fill in vain), and `rules recipe` stops before explaining. Free zones are not offered skip scopes they do not have (Super Bot Fight Mode, managed rules) — refused if passed anyway, noted for `rules add` — and their rate-limit period and timeout are fixed at 10 seconds.
- **Console data retention.** Hourly: expired sessions and OAuth states; the page of a snapshot whose link died more than 30 days ago (the record stays, marked); account audit entries older than a year; before/after comparisons older than 90 days.

## v1.7.0 — 2026-11-18

WAF made approachable, plus the live hour and the movers drill-down (v1.6, released with this version).

- **WAF basics and rule recipes.** A guide ("WAF basics" in the documentation, in English and Chinese) — order, verified bots, block vs challenge, narrow skips, sensitive paths — and ready-made rules: `protect-paths`, `ratelimit-paths`, `allow-service` (requires IPs, an ASN or a secret header — never a path or user agent alone), `allow-verified-bots` (`cf.client.bot`, never the user agent), `challenge-cloud-on-paths`. Each explains what it does, why and what it does not do; rules are placed by the skips → blocks → challenges order; protective recipes exclude verified bots. CLI: `flarehound rules recipes`, `flarehound rules recipe NAME`.
- **Plain-words explanations** of every rule ("If the path starts with /login and not a Cloudflare-verified bot → managed challenge") in `rules list`, the console and every review.
- **Skip rules fixed.** `rules add --action skip` produced a rule without the `action_parameters` Cloudflare requires, so it was rejected. `--skip rules,ratelimit,managed,bots,legacy` now says what is skipped (default: the remaining custom rules); a skip without it is caught before sending; turning a skip rule into another action drops its parameters.
- **The audit says how to fix.** `flarehound audit` and the console's audit page end with one fix per finding: a recipe with its inputs filled in, or a `rules move / delete / edit` command.
- **Console: WAF rules page.** Custom and rate-limit rules with explanations (read token); for admins of a console holding the write token: add from a recipe, enable / disable, move up / to top, delete, restore a backup — reviewed, bound to the ruleset version reviewed, TOTP-confirmed, audited first, backed up, read back.
- **Reliability.** Read-only Cloudflare requests (GraphQL analytics and REST GETs) are retried twice on connection errors, 429 and 5xx; writes are never retried. A failed live query is retried after 10 seconds instead of a minute.
- **Live hour on the overview** (v1.6). The last 60 minutes, queried from Cloudflare with exactly the watch's queries (`check.Runner.Measure`), ending 5 minutes ago for ingestion lag and marked *not settled*, against the 28-day same-hour baseline blended across the two clock hours the window spans. Shared by all viewers and re-queried at most once a minute; the newest settled hour moves below it, and comes back as the main view (with a note) when the live query fails.
- **Movers drill-down** (v1.6). Every user agent, ASN and uncached path on the movers and new-faces pages opens a breakdown for the movers' window and the same hour yesterday: paths, status codes, cache status, and ASNs of a user agent / user agents of an ASN — each drillable further, with the block link where it applies. Live queries, cached 10 minutes. Snapshots keep plain text (no links).

## v1.5.1 — 2026-11-18

- Sessions in use are no longer signed out after a fixed 12 hours: the session cookie now slides with the server-side session. Sessions waiting for their two-factor code keep their 5-minute lifetime instead of being extended.
- Blocks page: attempts are computed in the background (the page opens immediately, shows "computing…" and refreshes once), refreshed every 10 minutes, and cached under a stable whole-hour window — previously the cache never hit for blocks older than 7 days or without an audit record.
- Phones: wide tables (blocks, block log, users, snapshots, timeline, sessions, audit log) turn into one labelled card per row below 640 px.
- Fixed the Chinese "alerts in the last 24 h" line on the overview; tests now fail on any missing UI string, mismatched translation arguments or broken format verb.
- `docker-compose.yml`: optional `flarehound-console` service (profile `console`); `console --listen` overrides `console.listen`.

## v1.5.0 — 2026-11-18

- **Sign in with Google or GitHub** (`console.oauth`). A linked identity is an additional way into an existing local account: users link it from their account page after re-entering their password; an identity that is not linked signs in to nothing — no account is created, nothing is matched by e-mail. Two-factor sign-in, disabled accounts, forced password changes and `require_totp` still apply. Users unlink their own; admins see and remove anyone's on the Users page; linking, unlinking and sign-ins are audited.
- Authorization-code flow with PKCE; single-use `state` bound to the browser by a cookie (10 minutes); Google ID tokens checked for issuer, audience, expiry and nonce; GitHub identified by numeric user ID. Client secrets come from environment variables and are redacted from logs.
- The v1.3 `external_identities` table gains `display` and `last_used` (migrated automatically). `doctor` prints the redirect URIs to register and warns about plain-HTTP base URLs.

## v1.4.0 — 2026-11-18

- **Blocking from the console.** When the console process holds the write token (and only then — the watch must never have it), admins block, unblock and change expiry from the console. Movers and new faces offer a prefilled **block…** link. Every change is form → review → apply: the review shows the plan, the measured share and every guard-rail warning (shared code with the CLI); applying needs a review token bound to what was reviewed, the typed target for blocks that can hit real users, and a fresh TOTP code for accounts with two-factor sign-in. The guard rails run again server-side; the console audit log records the request under the account before Cloudflare is touched, then the outcome; changes are verified by read-back; the archive records the operator as `console:<account>`.
- **Undo** on every block-log record (opens the review of the inverse change), **change expiry** (`renew` audit events), live block list with attempts, rule quota and enforcer status.
- **Before / after**: the hour before and after each block — the target's requests, share and status codes, the zone total and the rule's attempts — computed automatically once settled.
- **Read-only snapshots** of the overview, movers and history: self-contained HTML (no script, no external resource, no tokens), downloadable, shareable through an expiring, revocable link that needs no sign-in.
- `blockcli` split into `Prepare` / `Execute` (the CLI behaves as before); `doctor` reports whether the console can block and warns when it can without mandatory two-factor sign-in.

## v1.3.0 — 2026-11-18

- **`flarehound console`**: a self-hosted web console, a separate process from the watch. Overview (newest settled hour vs the 28-day same-hour median, status against each alert line, 48-hour chart), movers (biggest risers and fallers by UA, ASN and uncached path, ranked by absolute change, with Top-N truncation shown as upper bounds), new faces (UA / ASN / path, first seen in 1 / 7 / 30 days), history (24 h / 7 d / 30 d with baseline band and a timeline of alerts, blocks and rule changes), WAF audit, and the block list (read-only). Server-rendered HTML with inline SVG charts, no JavaScript, strict CSP, mobile first, dark mode.
- **Accounts**: local accounts (admin / viewer), argon2id passwords, revocable server-side sessions, CSRF tokens, per-IP and per-account sign-in throttling and lockout, TOTP two-factor sign-in (optionally mandatory), step-up for account administration, single-use invitation links, an account audit log. First admin via a one-time setup link or `flarehound console init-admin`. Optional trusted-proxy identity header (Cloudflare Access and similar), honoured only from `console.trusted_proxies`. External identities are reserved for third-party sign-in (v1.5).
- **Isolation**: the console never reads the write token in this version; the watch and console heartbeats record whether the write token is in their environment and `doctor` reports it, along with the listen address, proxy setup and accounts.
- **Deep links**: with `console.base_url` set, alerts, daily reports and audit messages end with a link to the matching console view.
- The archive now also records uncached (dynamic) paths in the face history (`faces` dim `path`), so path new-faces work from this version on.

## v1.2.0 — 2026-11-17

- **Charts and HTML email** (`report.visuals`, default on). Requests per hour, last 24 h vs the day before, with the alert's hour shaded; a real-rendering (`dynamic`) chart when it matters. Drawn in pure Go on your machine, nothing uploaded. Email becomes HTML (plain-text alternative, inline charts, metric tiles, cost bar, top lists); Telegram, Discord and WeCom receive the charts as images; the JSONL channel saves them as files; `-dry-run` writes previews to the temp directory.
- ByteDance/BytePlus and other cloud providers recognised as hosting networks.

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
