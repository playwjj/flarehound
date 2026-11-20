# Changelog

All notable changes to FlareHound. Versions follow [semantic versioning](https://semver.org/); every `v*` tag publishes multi-arch Docker images (`linux/amd64`, `linux/arm64`).

## v1.18.0 — 2026-11-20

- **Storage hygiene: nothing FlareHound writes grows without a bound.** The archive already had a retention limit; four outlets did not. All are closed in code — no logrotate, no cron, no new settings:
  - **`flarehound doctor` shows the data directory**: `archive.db` (and its WAL) with the oldest hourly snapshot and whether large prunes return space, `console.db`, `alerts.jsonl` and its rotated copies, the `charts/` PNGs (count, size, oldest). A WAL of a few MB is SQLite's normal checkpoint size, not a leak.
  - **JSONL rotation**: past **32 MB**, `alerts.jsonl` → `alerts.jsonl.1` → `.2` → `.3` (the oldest dropped), between messages — every file still holds whole lines only, each written in one `O_APPEND`.
  - **Charts expire**: the PNG copies in `charts/` next to the JSONL file are removed **90 days** after they were written, once a day with the daily report (a dry run leaves them). The message itself stays in the archive.
  - **The archive prunes at one cut point**: besides hourly snapshots, **archived alerts** and **faces not seen** for `archive.hourly_retention_days` (default 400) now go too. Daily snapshots, the block log and rule backups/changes are kept for good.
  - **Space comes back on new databases**: `archive.db` and `console.db` created from now on use `auto_vacuum=INCREMENTAL`; a prune that removes ≥ 1,000 rows (typically after lowering the retention) hands the space back and the file shrinks. **Existing files are not migrated**: they level off but do not shrink (`doctor` says which kind a file is; [Disk space](https://playwjj.github.io/flarehound/archive/#disk-space) has the manual `VACUUM`).
  - **`docker-compose.yml` caps container logs**: every service uses the `json-file` driver with `max-size: 10m`, `max-file: 3`.

## v1.17.0 — 2026-11-20

- **IP location.** Every IP FlareHound shows now carries the country it is registered or routed in — the cheapest piece of context a block decision was missing (a residential address and a data-centre address call for different handling). Display only: it takes no part in detection, alerts, severity or block plans, and it is looked up when shown, never archived.
  - **Block review** (console and CLI): *IP location* next to the address's network (ASN and type) and its requests over the last 24 hours, with the measured share as before, and a small-print note: the location is where the address is registered/routed, not where its operator is — a residential proxy's exit country says nothing about who drives it, a data-centre address shows the data centre.
  - **IP board, drill-down, blocks page and block log**: `106.201.104.211 (IN)`, the country's name on hover (in the console's language).
  - **Alerts, daily report, every channel and `flarehound blocks`**: `106.201.104.211 [IN · India]`, with `report.language: zh` `106.201.104.211 [印度 (IN)]` — block candidates, top client IPs, most-blocked IPs, FlareHound blocks and the blocks expiring this week.
  - **Local library, no new data channel**: DB-IP's free country library (`dbip-country-lite`, MMDB, monthly, CC BY 4.0 — IP geolocation by DB-IP), read in-process (IPv4 and IPv6) with no third-party lookups. The Docker image bundles the month it was built in; `geoip.country_db` points at another file (GeoLite2-Country works too, bring your own); otherwise `<data dir>/country.mmdb` is used ahead of the image's copy.
  - **`flarehound geoip update`** downloads the newest lite library, checks it reads as a country library and replaces the file atomically (no token needed). Watch and console pick it up within 10 minutes.
  - **No library, or a broken one: nothing changes** — every IP is shown as before. `flarehound doctor` reports the library (type, build date, file date, networks), that none was found, or why a file is unusable.
- Changelog: the v1.16.2 entry appeared twice.

## v1.16.2 — 2026-11-19

- **A line whose baseline is still growing does not alert.** 52x became a metric in v1.15 (12:36). Within hours skoolopedia paged "origin unreachable" twice — `26 vs 0 (+999%)`, then `48 vs 3 (+1500%)` — for its ordinary 530/522 trickle (12–48 an hour, the origin serving throughout), and starngage's tile stayed red against "baseline 0". v1.16.1 stopped counting unmeasured hours as 0, but a median resting on one or two measured hours, or none, still let any normal hour clear "≥ 10 and ≥ 2× baseline". The same shape returns with every new metric (origin latency in v1.15, the CPU P99 in v1.16). Now every line read against the archive's same-hour median knows how many **measured** hours stand behind it:
  - **Immature baseline** — fewer than `thresholds.baseline_min_samples` (default **3**) earlier days measured the same hour: `origin_unreachable` (plain and bookkeeping rule alike) and `origin_slow` **do not fire** — also on a fresh archive where only yesterday's hour would decide. The watch logs "held: baseline accumulating (1/3 measured same-hour samples)". The CPU check treats an immature P99 as not measured, instead of judging it against one hour.
  - **Console**: such a tile is neutral — *baseline accumulating (1/3 days of this hour measured)* — neither red nor green, and does not count towards "needs attention".
  - **Daily report**: one line, in the first report after a metric started to be measured — "Baseline accumulating: edge 52x (origin unreachable) — newly measured; these lines stay quiet until 3 days of the same hour are measured (from about 11-22), then take over on their own." — not repeated afterwards.
  - **`doctor`**: per zone, the measured samples behind each newer metric for the newest hour ("baseline skoolopedia.com @15:00: accumulating, these lines stay quiet: unreachable 1/3 (~2 more day(s))").
  - **Takes over by itself**: the round the baseline has its samples, the line is judged by the current rules — starngage's tile then turns into *Edge 52x (bookkeeping background)* without clearing any state.
  - **Earlier false alarms are traced, not counted**: an archived alert that rested only on such lines while their baseline was immature (the v1.16.1 pages above) is left out of the console's alerts of the last 24 h and appears on the timeline as *alert on an immature baseline (not an anomaly)*.
- Archived hours now record what they measured, so a **measured 0** of 52x is a baseline sample and an unmeasured hour is not (hours from v1.15–v1.16.1 are still read by what they hold).
- Zones and metrics with enough samples behave exactly as before; comparisons made from two live windows (yesterday's same hour, the daily report's two days) are not affected. Without an archive (`archive.disabled`) there is nothing to measure maturity by, and the lines keep their old behaviour.

## v1.16.1 — 2026-11-19

- **Edge 52x: one judgement everywhere.** On Worker zones hundreds of 522/524 an hour are Cache API bookkeeping, not an unreachable origin (starngage: ~10,000 a day, the site healthy). v1.16.0 recognised that only in the daily report's footnote; the console tile stayed red and the `origin_unreachable` line still used its normally-zero threshold, so a real outage would have looked the same as every other hour. Now one judgement serves the alert evaluation, the console tile and the reports:
  - **Bookkeeping background**: the baseline's 52x are ≥ 90% 522/524 and the current window does not depart from it. The tile turns neutral — *Edge 52x (bookkeeping background)* — and no longer counts towards "needs attention" on the cross-zone home; reports add "check: bookkeeping background, not an outage — 522/524 are 99.7% of it, the same order as the baseline (×1.1), the origin keeps answering".
  - **Against such a background, `origin_unreachable` fires on a departure**: volume ≥ 3× the background (by at least `unreachable_min`), other 52x statuses (521, 523, 530 …) rising to ≥ 10% and ≥ `unreachable_min`, or origin-answered requests falling below half. The alert carries the status split and which of the three fired.
  - Zones with a normally-zero baseline, or a 52x trickle led by other statuses (skoolopedia's 530), keep the plain line (≥ `unreachable_min` and ≥ 2× baseline), unchanged.
- **The 28-day baseline no longer reads unmeasured hours as zero.** Hours archived before v1.15 never measured 52x; the same-hour median counted them as 0, which is why the tile showed "baseline 0" and would have for about two weeks. They are skipped now, and the median keeps a per-status split so the baseline's mix is known.
- **Blocks live check: no more structural zero.** Firewall events can reach the dataset 30–60 minutes late, so the 15-minute window read 0 for a block that was busy. The window is now **the last hour**, with a **3-hour look-back** for the last block, and the page says how far the event data reaches: "last hour: 493 stopped · last knock 13:02", or "last hour: no events landed yet · last block 12:58 (33 min ago) · event data up to 12:59", or "no blocks in the last 3 hours". Same in `flarehound blocks` (`LIVE 1h`).

## v1.16.0 — 2026-11-19

- **Expired blocks are lifted by the console.** Until now only a separate `flarehound enforce` process lifted blocks whose `--for` had passed; a deployment without it (watch + console only) showed a block as expired while the rule kept blocking in Cloudflare — over-blocking that grows riskier as residential IPs are reassigned. The console is the one long-running process holding the write token, so it now runs the expiry pass itself every 5 minutes, through the same read-back verified unblock, recorded as `system:expiry` in both the block log and the console audit log. It writes the expiry heartbeat, so the blocks page's "nothing is lifting expired blocks" warning and `doctor` stay accurate. `flarehound enforce` still works (CLI-only setups, cron) and is no longer required next to a console with the write token.
- **Block rules go where they work.** A new FlareHound rule used to be appended at the end, behind the zone's challenge rules (a confirmed bad IP kept eating challenge pages before reaching the block) and behind every skip rule. It now goes **after all skip rules** (your services and verified crawlers stay exempt) and **before your first challenge or block rule**. Review says where — "inserted at #4, after «…» and before «Protected Pages» (managed_challenge)" — and the result is read back. A FlareHound rule created before v1.16 that sits elsewhere is **moved once**, on its next block (review says "moves once from #18 to #4"); adding members afterwards never moves it. Your own rules are never edited.
- **Bypass warning at review.** Each skip rule ahead of the block rule is evaluated against the target and its user agents of the last 24 hours (the WAF audit's evaluator). A skip that certainly matches — the target itself, or a user agent it sends — shows a red warning: "this target is let through by skip rule #8 «UA allowlist» (skip) — its user agent … (75% of its requests) matches it: the block may have no effect on it".
- **Live check for blocks.** The blocks page and `flarehound blocks` show the **last 15 minutes**, queried live: "blocked 312 times, last knock 14:07". Paid plans read the firewall events on the block's own rule; plans without firewall events count the target's requests stopped at the edge. The archived attempts stay alongside; this narrows "did it take effect?" from hours to minutes.
- **Free zones get attempts.** Without firewall events, IP blocks' attempts were "n/a" for good. They are now approximated from the IP board archive (each hour's top 50 IPs stopped at the edge, kept since v1.14) and marked as such — "≈415 (approx., from the IP board archive; last on the list 11-17 08:00)" — in the console, `flarehound blocks` and the daily report. An IP outside an hour's top 50 adds nothing that hour, so the last hour it made the list is shown next to the sum.
- **Daily report: expiring this week.** Blocks expiring within 7 days, each with what its attempts say: still knocking → consider renewing; quiet → it will be lifted automatically.
- **Worker CPU alerts check themselves.** The Worker query now also takes the CPU **P99** (same query, no extra request). Every CPU line carries the three numbers — "check: P50 +50.5%, P99 +12.0%, calls −18.0%" — and their reading: P50 and P99 up with calls holding is *really more expensive* (code, a dependency, heavier requests); P50 up with the tail flat and calls down is a **mix change** (cheap calls left, e.g. a flood receding, and the median moved) — reported at **low severity** with its own hypothesis instead of the old "deploy change or slow code path". Reports show P50 and P99 side by side. Hours archived before the upgrade have no P99; the check then says so and the old reading stays.
- **Edge 52x footnote.** On Worker zones a steady background of 522/524 is edge bookkeeping, not an outage (starngage: ~10,000 a day while the site was fine). When the 52x count is present in both windows, not rising, mostly 522/524, and the origin keeps answering, reports add "mostly edge bookkeeping entries, not an outage" and the console tile reads *Edge 52x (mostly bookkeeping entries)* in the OK state. The alert line is unchanged.
- **Two-factor hint in the console.** A console holding the write token without `console.require_totp` shows its admins a banner (it was a startup log line) until the option is turned on, or an admin keeps it off explicitly — that choice is recorded in the audit log.

## v1.15.0 — 2026-11-19

- **Origin view for sites on a VPS behind the proxy.** A flood costs a Worker site money; it costs a site on one small VPS its availability. FlareHound now watches the origin itself, not just its 5xx count. No new permission or token: the fields are in the same adaptive dataset, on every plan including Free.
  - **Origin unreachable** (new line `origin_unreachable`): the edge's own 52x answers (520–526, 530) mean Cloudflare could not reach the origin at all. These were never counted before: the origin answered nothing, so they are not origin 5xx. ≥ 10 per hour (`thresholds.unreachable_min`) from a normally-zero baseline pages at once, at high severity, with the status split (522 ×340) and an "origin down" hypothesis.
  - **Origin slow** (new line `origin_slow`): P95 time to first byte (the application computing) and of the full response (plus transfer), over the requests the origin actually answered. Fires at +100% **and** ≥ 1 s (`origin_slow_up_pct`, `origin_slow_min_ms`), against yesterday and the 4-week median like every volume line. The hypothesis says whether it slowed under more uncached load or with load flat (the machine itself), and first byte vs transfer; the attribution lists where the origin's work goes by path.
  - **Origin 5xx in detail**: as a share of origin answers next to the count (a falling-traffic origin cannot hide behind a small count) and split 502 / 503 / 504.
  - Reports and alerts show the origin's P95s (and TCP/TLS connect when non-zero). The console overview gets *Origin unreachable*, *Origin first byte P95* and *Origin full response P95* tiles; they fold away on zones the edge serves (fewer than 100 origin-answered requests an hour), so Worker sites see no clutter. A zone with 52x over the line tops the cross-zone home. `flarehound doctor` shows whether origin latency is readable per zone.
  - Archived hours from before the upgrade have no origin latency: they read "n/a" and the origin-slow line waits for the baseline to fill. Older settings overlays get the new lines' defaults.

## v1.14.2 — 2026-11-19

- **Console:** "mark as known" is a compact link now, not a button — the same action with less visual weight in the face lists.
- **Docs:** Chinese README ([README.zh.md](https://github.com/playwjj/flarehound/blob/main/README.zh.md)); SPEC.md is frozen — it keeps the design rationale, while the README and the docs site describe the product as it stands.

## v1.14.1 — 2026-11-19

- **IP board: crawlers no longer fill it.** On a busy site each real Googlebot address does thousands of requests an hour, so a run of `66.249.66.x` took the top places.
  - Addresses Cloudflare verified as a known bot (`verifiedBotCategory`, every plan) are split off and folded at the bottom as *Verified bots*, with their total; no block link there. A fake crawler sending Googlebot's user agent is not verified and stays on the board. The watch now archives them apart (`bot_ips`); the query takes 100 addresses so the board still gets its 50 others.
  - IPv4 addresses are summed per /24 when two or more of one /24 are listed (as IPv6 per /64), so a scraper walking a range is one row: "68.166.168.0/24 (4 addresses)", its largest addresses listed beneath and each drillable; *block…* blocks the /24.
  - Hours archived by v1.14.0 have bots mixed in; an address verified in any later hour moves to *Verified bots* for the whole 24 h.

## v1.14.0 — 2026-11-19

- **IP board** (new console tab *IPs*): which client addresses keep hitting the zone, at a glance.
  - **Last 60 minutes** live, or **24 h** from the archive — the watch now keeps each hour's top 50 client IPs (with their ASN) and top 50 IPs stopped at the edge (two extra queries per round). The 24 h view fills in from the first hour after upgrading; until then it says so and points at the live hour.
  - Per address: requests, share of the zone, **hours present** out of 24 with an hour strip, the share stopped at the edge, the network, and *block…* into the usual IP block flow (*blocked by FlareHound* when an active IP block already covers it). Ranked by persistence by default, or by requests.
  - IPv6 is summed per /64 (clients rotate inside one); a /64 links straight to a CIDR block.
  - Big crawlers do not crowd it: ranking single addresses already plays them down (they spread over thousands of addresses); addresses in networks you marked known are folded at the bottom with their total; crawler networks (Googlebot, Bingbot, …) are labelled but never folded, since the same network carries other traffic (AS8075 is Bingbot and Azure alike).
- **Drill-down by IP**: any single address (from the IP board, or the client-IP list of another drill-down) breaks down into its paths, status codes, cache status and user agents.

## v1.13.1 — 2026-11-18

- **Client IPs in the drill-down.** Every drill-down (user agent, ASN, uncached path) gains a client-IP breakdown — top 10, share of the entry, same hour yesterday — with a *block…* link per address into the usual confirmed IP block flow (guard rails unchanged). One line reads it: an address carrying ≥ 30 % of the entry says blocking that IP stops most of it; none reaching 1 % says the sources are dispersed and per-IP blocking will not help — the alerts' own rule. Until now client IPs reached only the alert notifications.
- **Live faces, tidied.** The overview's loudest user agents and ASNs sit in their own card with column headers, a share of the window's requests (with a small bar) and drill-down links; an empty user agent reads "(no user agent)" instead of a blank row.

## v1.13.0 — 2026-11-18

- **"What is rising right now" answerable in the console.** Three views for the everyday question the yesterday-anchored tiles could not answer:
  - **Blocked board** on the movers page: sources (ASN, user agent) ranked by the requests stopped at the edge in the movers' window — 403 with no origin response, so a 403 the origin itself returned is not counted. A rise in the totals is attributed at a glance — old faces knocking, not a breach. Names open the drill-down. Live queries, cached 10 minutes (a failure 1 minute).
  - **Trend strip** on the overview: the last six clock hours overlaid on the same hours yesterday, ending with the live 60 minutes against the same 60 minutes yesterday — the momentum view. No query of its own (it reuses the cached live measurement).
  - **Live faces**: the live hour lists its five loudest user agents and ASNs under the tiles, labelled unsettled.
- Console: space between the live hour and the "latest settled hour" section on the overview.

## v1.12.1 — 2026-11-18

- Console: after the two-factor step-up, you are taken back to the page the action started from (e.g. "Mark known" on new faces) instead of the users page. The console sends no Referer, so the step-up now follows the form's own return address.
- Console: the logo in the header and a favicon.

## v1.12.0 — 2026-11-18

- **E-mail over HTTPS.** `notify.email.provider` = `resend` sends through [Resend](https://resend.com)'s API (port 443) for hosts that block outbound SMTP; the key comes from `api_key_env`. Same text, HTML and inline charts; console password-reset mails follow. Also settable in the console (`email_provider`, `email_api_key_env`). `smtp` stays the default.

## v1.11.1 — 2026-11-18

- Console: the "Mark known" button no longer crowds the name and tags before it (overview, movers, drill-down).

## v1.11.0 — 2026-11-18

- **WAF audit coverage per zone.** With several zones, each zone's coverage check probes only its own hosts (global `waf_audit.hosts` are filtered to the zone and its subdomains), and sensitive paths can be set per zone (`cloudflare.zones[].waf_audit.sensitive_paths`, plus optional `hosts`). The global list is only the default — for the single zone, or with several for the zones the global hosts belong to (the first zone when none are set). A zone without a list of its own now says "coverage not configured" instead of being scored against another site's paths and hosts; `doctor` says so too. The rule-interaction analysis is unchanged.

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
