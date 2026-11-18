# Rule changes

New to WAF rules? Read [WAF basics](waf-guide.md) ([中文](waf-guide-zh.md)) and start from the recipes.

The execution module applies rule changes — including the challenge, rate-limit and cache suggestions from alerts — to three Cloudflare phases:

| `--phase` | Cloudflare phase | Write-token permission |
|---|---|---|
| `custom` (default) | `http_request_firewall_custom` — custom (WAF) rules | Zone → WAF: Edit |
| `ratelimit` | `http_ratelimit` — rate-limit rules | Zone → WAF: Edit |
| `cache` | `http_request_cache_settings` — cache rules | Zone → Cache Rules: Edit |

It uses the same separate write token as [blocking](blocking.md) (`CF_WRITE_TOKEN`) and needs the [archive](archive.md) for backups and the audit log. With several zones configured, add `--zone NAME|ID`.

## Commands

```bash
flarehound rules list [--phase custom|ratelimit|cache]      # each rule with a plain-words explanation
flarehound rules recipes                                     # ready-made rules, explained
flarehound rules recipe NAME [--path P] [--action A] [--ips IPS] [--asns ASNS] [--header NAME --secret-env VAR] [--skip SCOPES]
flarehound rules add --action ACTION --expr EXPR --desc TEXT [--before N|ID] [--disabled] [--skip SCOPES]
flarehound rules edit N|ID [--expr EXPR] [--action ACTION] [--desc TEXT] [--enabled true|false]
flarehound rules delete N|ID
flarehound rules move N|ID (--before N|ID | --last)
flarehound rules backups                  # snapshots taken before each change
flarehound rules restore BACKUP_ID        # put a phase back as it was
flarehound rules log                      # execution audit log
flarehound ratelimit add --path PATTERN [--requests 20 --period 10 --timeout 10 --action managed_challenge]
flarehound cache add --path PATTERN [--ttl 1d]
```

- `N` is the rule's position in `rules list`; `ID` is the Cloudflare rule ID (or its `ref`).
- `--path` takes a pattern with `*` wildcard and turns it into an expression (`/x` → `eq`, `/x*` → `starts_with`, other `*` patterns → `wildcard`); `--expr` takes a full expression instead.
- `rules add` needs `--action` (a Cloudflare action such as `block` or `managed_challenge`), `--expr` (or `--path`) and `--desc`.
- **Skip rules** (`--action skip`) must say what they skip: `--skip rules` (the remaining custom rules — the default), `ratelimit`, `managed` (managed rules), `bots` (Super Bot Fight Mode), `legacy` (security level, browser integrity check, UA blocking, zone lockdown …), comma-separated. FlareHound builds the `action_parameters` Cloudflare requires; editing a skip rule into another action removes them.
- **Recipes** build a complete rule from a few inputs and place it by the skips → blocks → challenges order: `protect-paths`, `ratelimit-paths`, `allow-service`, `allow-verified-bots`, `challenge-cloud-on-paths`. Each prints what it does, why, the rule in plain words and any caveat before the usual confirmation. A secret header value is read from the environment variable named by `--secret-env`, never from the command line. See [WAF basics](waf-guide.md#recipes).
- `ratelimit add` builds a per-IP rule (counted per IP and data center): `--requests` per `--period` seconds, mitigation `--timeout` seconds, default action `managed_challenge`.
- `cache add` builds a rule that makes matching requests eligible for cache with an edge TTL overriding the origin (`--ttl`, default `1d`; Go durations or `Nd`).
- `--observe 5m` (custom and rate-limit changes) watches the changed rule's firewall events afterwards and reports the count. Zero only means "no matching traffic yet or not ingested"; on plans without firewall events it is skipped.

Examples:

```bash
flarehound rules add --action managed_challenge \
  --expr 'starts_with(http.request.uri.path, "/login")' --desc "challenge login" --before 1
flarehound rules edit 3 --enabled false
flarehound rules move 3 --last
flarehound ratelimit add --path '/rank' --requests 20 --period 10
flarehound cache add --path '/assets/*' --ttl 1d
```

## Safety

Every change goes through the same steps:

1. **Show** the full change: all fields and the insert position for an add, field-by-field `old → new` for an edit, the full rule for a delete, positions for a move, and every rule that comes back / is removed / is changed / moves for a restore. Warnings are printed (e.g. inserting ahead of existing rules, disabling or deleting a protection).
2. **Confirm** with `y/N`. There is deliberately **no `--yes`** — passing it is an error — and no batch mode.
3. **Back up** the whole phase first, exactly as Cloudflare returned it: to the archive (`rule_backups`) and to `backups/<zone>/<phase>-<time>-v<version>.json` in the data directory (mode 0600).
4. **Apply**, then **read back** and compare every field set by the change and the rule's position (fields Cloudflare adds by itself are allowed). A mismatch is reported as an error together with the restore command.
5. **Log** to the append-only `rule_changes` table: time, phase, operation, rule, before/after JSON, backup ID, verified or not, details (including API rejections). View it with `flarehound rules log`.

Guard rails:

- Expressions are syntax-checked locally with FlareHound's rules-language parser before anything is sent.
- Quotas per plan are checked before adding:

| Phase | Free | Pro | Business | Enterprise |
|---|---|---|---|---|
| Custom rules | 5 | 20 | 100 | 1,000 |
| Rate-limit rules | 1 | 2 | 5 | 100 |
| Cache rules | 10 | 25 | 50 | 300 |

- On Free, the rate-limit period and mitigation timeout must both be 10 seconds.
- Rules owned by the blocking module (`flarehound-` prefix) cannot be changed here — use `block` / `unblock`.
- Rules are handled as raw JSON, so fields FlareHound does not model (skip parameters, rate-limit details, logging …) survive edits and restores.
- New rules get a `ref` starting with `fhx-`, used to find them on read-back.

## Restore

`flarehound rules restore BACKUP_ID` replaces the whole phase with the snapshot. It takes a fresh backup first, so a restore can itself be undone, and is confirmed and verified like any other change. Every successful change prints its undo command:

```
Done — … (verified by read-back). Backup #12: data/backups/example.com/custom-20261117-091500-v7.json
Undo: flarehound rules restore 12
```

Cloudflare matches rules by `ref`: in a live test, rules with a `ref` **kept their IDs** after a whole-phase restore, so their hit history continues. If the backup contains rules without a `ref`, FlareHound warns that they may get new IDs. Restoring a phase also restores FlareHound's blocking rules in it — run `flarehound blocks` afterwards to reconcile.
