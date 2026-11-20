# WAF basics

For people setting up Cloudflare WAF custom rules for the first time: five principles, then how to apply them with FlareHound's **rule recipes**, then the common mistakes. Every change shows the complete rule and waits for your confirmation; the phase is backed up first, the result is read back, and any change can be restored.

## Five principles

**1. Order is everything.** Custom rules run top to bottom; the first *block* or *challenge* that matches ends it, and a *skip* rule lets a request past what it skips. Keep **skips first, then blocks, then challenges**. FlareHound's recipes place their rules accordingly.

**2. Let search engines in with `cf.client.bot`, never by user agent.** `cf.client.bot` is true only after Cloudflare has checked the bot's IP and reverse DNS (Googlebot, Bingbot …). Anyone can put "Googlebot" in a user agent; a skip rule on it is an open door (the WAF audit flags such rules as forgeable). Usually you need no allow rule at all: add `and not cf.client.bot` to your block and challenge rules, as FlareHound's own rules do.

**3. Block or challenge.**

| Block | Managed challenge |
|---|---|
| Scrapers on cloud / hosting ASNs | Whole countries |
| Single attacking IPs | Home and mobile network ASNs |
| A stable bad user agent | Login, admin, search, API paths |
| Paths no outsider should reach (`/.env`) | When in doubt |

A managed challenge stops automated clients and costs a person one click. When unsure, challenge first, watch, then decide whether to block.

**4. Skip narrowly.** Monitors, payment callbacks and webhooks must get through — tie the exemption to something a stranger cannot fake: source IPs, the network (ASN) or a secret header only that service sends, and the paths it needs. Skip only what you must: the remaining custom rules by default; rate limiting, managed rules or Super Bot Fight Mode only when needed.

**5. Protect sensitive paths on their own.** Login, admin, search and APIs get a challenge *and* a per-IP rate limit. The WAF audit lists sensitive paths without protection (from `path_rules`, `daily.paths` and `waf_audit.sensitive_paths`).

## Recipes

```bash
flarehound rules recipes          # all recipes, explained
flarehound audit                  # ends with "How to fix", with commands to run
```

In the console: **WAF rules → Add a rule from a recipe**, or **Fix with a recipe** under "How to fix" on the WAF audit page.

| Recipe | For | Example |
|---|---|---|
| `protect-paths` | Challenge login / admin paths (verified bots excepted) | `flarehound rules recipe protect-paths --path '/login*, /admin*'` |
| `ratelimit-paths` | Challenge an IP sending too many requests | `flarehound rules recipe ratelimit-paths --path '/login*' --requests 20` |
| `allow-service` | Let a monitor / webhook through (IPs, ASN or secret header required) | `flarehound rules recipe allow-service --ips 203.0.113.10 --path '/webhooks/*'` |
| `allow-verified-bots` | Let verified search-engine bots past other rules | `flarehound rules recipe allow-verified-bots` |
| `challenge-cloud-on-paths` | Challenge cloud servers on sensitive paths | `flarehound rules recipe challenge-cloud-on-paths --path '/login*'` |

Never put a secret header value on the command line (shell history): put it in an environment variable and pass `--secret-env NAME`; in the console, type it into the form's password field.

Before you confirm you see the recipe's explanation, the rule in plain words ("If the path starts with /login and not a Cloudflare-verified bot → managed challenge"), every field, the insert position, the quota after, and warnings.

## Writing rules yourself

```bash
flarehound rules list                       # every rule with a plain-words line
flarehound rules add --action managed_challenge --expr '...' --desc '...'
flarehound rules add --action skip --skip rules,ratelimit --expr '...' --desc '...'
flarehound rules edit 3 --enabled false     # disable and watch before deleting
flarehound rules move 3 --before 1
flarehound rules restore 12                 # put the phase back as it was
```

`--action skip` must say what it skips: `--skip rules` (the remaining custom rules, default), `ratelimit`, `managed` (Pro and above), `bots` (Super Bot Fight Mode, Pro and above — Free's Bot Fight Mode cannot be skipped by rules), `legacy` (legacy security features), comma-separated. Cloudflare rejects a skip rule without it; FlareHound tells you before sending.

## Common mistakes

- **Allowing Googlebot by user agent** — forgeable. Use `cf.client.bot`.
- **A skip rule at the bottom** — the blocks above already acted. Skips go first.
- **A challenge ahead of a block** — traffic matching both meets the challenge first; the block acts only after it is passed, and its hits hide behind the challenge's, so you cannot tell whether it works. Put the definite verdict (block) first.
- **Blocking countries or home-network ASNs** — hits real people. Challenge.
- **"Let my office in" by path or user agent** — lets everyone in. Tie it to IPs or a secret header.
- **Rate limits on Free** — one rule, 10-second period and timeout.
- **Quota full** — Free 5, Pro 20 custom rules. Merge rules with the same action using `or`; the audit lists candidates.

## Undo

Every change backs up the whole phase first (archive and a JSON file under `data/backups/`). `flarehound rules backups` lists them, `flarehound rules restore ID` puts one back; in the console, **Backups** at the bottom of **WAF rules**. A restore is backed up too, so it can be undone.
