# Rule simulator

A block decision is never about one target: it is a WAF expression — a set of ASNs, a country, a user-agent condition, a path, and the exemptions that keep verified crawlers and your own services out. What that expression *does* is not the volume of its target. Three examples from one week on a live zone:

- **AS30633 looked four times bigger than it was.** About 147,000 requests a day, listed as a block candidate. But ~111,000 of them were ExaSearchBot, a Cloudflare-verified bot that `and not cf.client.bot` exempts. What the rule could actually stop was ~36,000 a day.
- **An exemption that should have been written before the block.** A rule on AS45102 also caught rednote (not a verified bot, ~5,000 requests a day, all from that network), which the owner had decided to leave alone. The `and not (http.user_agent contains "rednote")` branch was added afterwards.
- **A rule nobody could size.** A referer branch ("referer is exactly the home page") was sized only by watching the challenge count after it went live.

The simulator replays a draft expression against the last days of real traffic and answers before the rule exists. **It only reads.** It creates no rule and no block plan.

## Running it

```bash
flarehound simulate --zone starngage.com --expr '(ip.geoip.asnum eq 30633 and not cf.client.bot)' --action challenge
flarehound simulate --expr 'http.user_agent contains "python-requests"' --days 1
flarehound simulate --expr '…' --date 2026-11-17      # one local day
flarehound simulate --expr '…' --json                 # the report as JSON
```

Read token only (`Zone → Analytics: Read`); the watch side can run it. Window: the last **7 days** (`--days 1` for 24 hours, or `--date` for one day in `schedule.timezone`), ending **an hour ago** — the last hour's data is still landing.

In the console: **Simulate** tab (any signed-in account). Composition rows link to the drill-down.

**At block review** the simulation runs by itself: for an ASN, country or user-agent block, the review simulates the rule this target becomes (`(ip.geoip.asnum in {N}) and not cf.client.bot`, …) and shows the verdict above the confirm button, in place of the single-target measurement. IP blocks keep the light measurement. If the expression cannot be evaluated on the zone (Free plan, no country dimension …), the review falls back to the measurement and says why.

## What the report says

1. **Gross matches** — requests the expression matches without its own `and not …` branches, and with them (what the rule matches); share of all traffic and of dynamic (origin) traffic; split per day.
2. **Exemptions** — gross minus matches: what "the rule would block" vs "the rule actually blocks". Each top-level `and not …` branch is counted on its own.
3. **Net new** — the number that counts: the matches minus what existing rules already block or challenge (firewall events filtered by the same expression; block, challenge, JS challenge, managed challenge — not their outcomes, so a request is not counted twice). Counted against the whole rule set, not this rule's future position.
4. **Composition** — top 5 paths, user agents, client IPs (with [IP location](configuration.md#geoip)), countries; top networks when the expression is not bound to ASNs. Known sources (`known_faces`) among the matches are listed.
5. **Action** — `block`: people who would pass a challenge are blocked too. `challenge`: a pass-rate estimate is not available yet.
6. **Confidence label** — one per report:
    - *approximate (sampled data)*;
    - *approximate (includes a cross-dataset estimate)* — net new joins two datasets;
    - *upper bound* — a sub-expression could only be widened (the referer, see below); every number carries `≤` and the sub-expression is named.
7. **Verdict line** — one sentence in the guard rails' terms: nothing matched; a residential network in the matches; a known source hit; verified bots ≥ 20 % of the matches; net new < 1 % of all traffic; net new far below the gross. Example: *Gross 147,300, of which 111,493 exempted (verified bots 111,493), net new ≈ 35,800 (0.2 % of all traffic) — consider a challenge, or no action.*

Numbers are in FlareHound's units, cleaned like the reports (on zones with Workers, empty-UA entries — Worker bookkeeping — are left out everywhere and counted on their own line); once [calibrated](archive.md#calibration), counts also show their dashboard equivalent.

## What can be evaluated

There is **no replay API**. GraphQL analytics are sampled, aggregated datasets; per-request logs are Logpush (Enterprise), which FlareHound does not use. The simulator translates the expression into dimension filters:

| Tier | Fields | |
|---|---|---|
| Exact (sampled) | `ip.src` (single addresses), `ip.geoip.asnum` / `ip.src.asnum`, `ip.geoip.country` / `ip.src.country`, `http.user_agent`, `http.request.uri.path`, `http.request.uri.query`, `http.host`, `http.request.method`, `cf.client.bot`, `cf.verified_bot_category` with `eq` `ne` `in` `contains` `starts_with()` `ends_with()`, combined with `and` `or` `xor` `not` and parentheses | Negations are pushed down to each comparison |
| Upper bound | `http.referer` — only the referer's **host** is a dimension (paid plans). `eq "https://site/"` is counted as every referer from `site`. Not allowed under a negation (it would be neither a count nor a bound). `http.referer eq ""` (no referer) is exact | Label *upper bound*, sub-expression named |
| Not evaluable | headers, cookies, bodies, `matches` (regex), `wildcard`, `cf.threat_score` / bot score, rates, `lower()` and other functions, `$list` references, IP ranges (CIDR) | Named with the reason — **no numbers at all**, never a silently dropped condition |

Every field is checked against what the zone's plan exposes (`flarehound doctor` shows a *rule simulator* row per zone). On **Free** there is no ASN dimension and no firewall-events dataset: an ASN expression is *not evaluable on this zone*, and net new is not available — the report says so instead of filling the gap from another source.

## Budget and cache

At most **24 GraphQL queries** per simulation (typically 15–19), four at a time. The same simulation within **10 minutes** comes from the cache (console; the review and the apply share it).

## After the block

The simulation shown at review is **kept with the block record** (archive table `block_sims`). The before/after comparison (console and daily report) then adds a line: *predicted net new ≈ 1,490/h (simulation at review); actual 1,320 stopped in the hour after (−11 %)* — so the prediction's error stays visible. "Actual" is the rule's firewall events; on plans without them it says it cannot be counted.

## Not done

- No one-click apply: a report produces no block plan and no write path.
- No per-request replay, no Logpush, no raw logs on disk: sampling is the precision limit.
- No cross-zone simulation: expressions and rule sets are per zone.
- Not yet: the rule's position (a skip rule ahead letting traffic through, an earlier block taking it first), challenge pass rates, `$list` expansion.
