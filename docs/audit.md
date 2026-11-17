# WAF rule audit

FlareHound reads your zone's custom rules — read-only, with the read token — and checks them the way a reviewer would. It never changes them.

```bash
flarehound audit                     # all zones
flarehound audit --zone example.com
```

**Permissions:** Zone → WAF: Read on the read token (rulesets and the IP Access Rules allow-list); Zone → Zone: Read optionally, for the quota check. Without WAF: Read the audit reports "unavailable" with the reason, and the watch is unaffected. See [permissions](permissions.md).

## Where it appears

| Where | What |
|---|---|
| `flarehound audit` | The full audit: rule list, every coverage result, hit table |
| Daily report | One line when clean; otherwise only the items that need attention |
| Intraday round | The ruleset version is read each round (one REST call). When it changes, the audit runs again and, if it finds problems, sends a separate `kind: "audit"` message. The first version seen is only recorded. |

Turn it off with `waf_audit.disabled: true`.

## Checks

### Coverage gaps

Sensitive paths = `path_rules` + `daily.paths` + `waf_audit.sensitive_paths`. Each pattern becomes one probe path (`/login*` → `/login`, `/u/*/edit` → `/u/x/edit`), probed on every host in `waf_audit.hosts` (default: the zone name). Walking the enabled rules in execution order:

| Result | Meaning |
|---|---|
| **exempted** | A skip rule that skips all later custom rules always matches first |
| **covered** | A block / challenge / js_challenge / managed_challenge rule always matches (noted if a conditional skip rule ahead may exempt some requests) |
| **partial** | Only conditional protection (e.g. only for one user agent) |
| **gap** | No protective rule applies |

### Ordering and redundancy

Only what can be proven is reported:

- a protective rule entirely covered by a skip rule ahead of it — it never takes effect;
- a skip rule ahead that overlaps a protective rule on a sensitive path — bypassable there;
- a rule entirely covered by an earlier **Block** rule — it never fires (challenge rules do not count as shadowing);
- duplicates — same normalised condition, same action.

### Exemptions

Every skip rule is listed with what it skips and the fields in its condition. A condition built only from fields any client can forge — user agent, referer, host, path / URI / query, method, HTTP version, `X-Forwarded-For` — is flagged "anyone can forge this", with advice to bind it to `ip.src`, `ip.geoip.asnum` or a secret header (and `cf.client.bot` for crawlers). Cookies and other request headers are not considered forgeable, since they may carry a secret. Allow entries in IP Access Rules are listed too, because they bypass the WAF entirely.

### Hits and zombie rules

Where the firewall events dataset exists, hits per rule are counted day by day over up to 30 days and shown for 7 days and the whole window. The window is clamped to how long the zone keeps firewall events (some plans keep only 3 days; reaching past that gets the query rejected), and the report says how many days it covers. A protective rule with **no hits in 30 days** that was not modified in the last 30 days is reported as a zombie — only when the full 30 days are covered; on a zone that keeps 3 days, three quiet days prove nothing, so no zombie verdict is made — reported, not removed: quiet is not useless. Skip and log rules are never zombies. On plans without the dataset (Free) the section says "not available" and draws no zero-hit conclusions.

### Quota

When the rule count reaches 80% of the plan's custom-rule limit (Free 5 / Pro 20 / Business 100 / Enterprise 1,000), the audit says so and lists protective rules with the same action that could be merged with `or` (FlareHound's own rules and rules with action parameters are excluded).

### Rule names

Reading the ruleset also gives FlareHound each rule's description, so firewall events in reports show names instead of IDs. [`rule_names`](configuration.md#rule_names) still overrides them.

## How it evaluates rules

FlareHound ships its own parser for the Cloudflare rules language — `and` / `or` / `xor` / `not` and their symbol forms, comparisons including `contains`, `matches`, `wildcard`, `strict wildcard` and `in`, sets and ranges, `$lists`, function calls, raw strings and header map access. Rules are evaluated with **three-valued logic** against probe requests that fix only `http.host` and the path: each rule is "always matches", "never matches" or "depends on other fields". A rule it cannot parse is listed as a parse failure and excluded from the other checks rather than guessed at.
