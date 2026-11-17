# One-click blocking

Alerts name the culprit and print the command that blocks it. Blocking is a separate, explicitly confirmed action that uses its own **write token** (`CF_WRITE_TOKEN`, see [permissions](permissions.md#write-token-cf_write_token)); the watchdog process never reads it.

```bash
flarehound block asn 207990 --action block --for 24h
flarehound block ip 45.13.7.9
flarehound block ip 45.13.7.0/24 --reason "scraper, 11-17 incident"
flarehound block country XX --action challenge
flarehound block ua "BadBot/1.0" --for 7d
flarehound unblock asn 207990
flarehound blocks              # everything blocked, attempts over 7 days, expiry
flarehound enforce             # long-running: lifts blocks whose --for has passed
```

With several zones configured, add `--zone NAME|ID`.

## Targets and defaults

| Target | Accepts | Default action | Cloudflare object |
|---|---|---|---|
| `ip` | IPv4/IPv6 address or CIDR (not wider than /8 for IPv4, /16 for IPv6) | block | Account IP list `flarehound_block` + rule `flarehound-ip-block` (`ip.src in $flarehound_block`); otherwise an expression rule |
| `asn` | `207990` or `AS207990` | challenge | Rule `(ip.geoip.asnum in {…}) and not cf.client.bot` |
| `country` | 2-letter ISO code (plus `T1` for Tor) | challenge | Rule `(ip.geoip.country in {…}) and not cf.client.bot` |
| `ua` | User-agent substring, 3–200 characters | block | Rule `(http.user_agent contains "…" or …)` |

`--action` is `block` or `challenge` (Managed Challenge). ASN and country rules keep verified bots allowed, so a block never takes out search engines.

## What FlareHound touches

- Only its own objects: one custom rule per target type and action, named `flarehound-<type>-<action>` (e.g. `flarehound-asn-challenge`), the list `flarehound_block`, and IP Access Rules whose notes start with `flarehound:`. Your rules are never edited or reordered; new rules are appended after them.
- Targets of one type are merged into one rule, so the custom-rule quota (Free 5 / Pro 20 / Business 100 / Enterprise 1,000, shared with your rules) is barely touched. Unblocking the last entry deletes the rule and frees the slot.
- Expressions have a fixed format so they can be read back. If you hand-edit a FlareHound rule into a shape it does not recognise, FlareHound refuses to modify it. A rule that would exceed 4,096 characters is refused.
- The IP list is used when `cloudflare.account_id` is configured and the token has Account Filter Lists: Edit; otherwise IPs go into an expression rule (still one rule).
- When the custom-rule quota is full, IPs and ASNs fall back to **IP Access Rules** (no quota, but no condition logic — verified bots are *not* exempt; IPv4 ranges only /16 or /24, IPv6 only /48 or /64). Countries and user agents have no fallback.
- Cloudflare is the source of truth: the current blocks are read from Cloudflare every time.

## The confirmation step

Before anything changes, FlareHound prints the plan: zone, target (for ASNs with network type and name), action, mechanism and quota, the rule expression afterwards, the target's measured share of the last settled hour's excess over the same hour yesterday (IPs, ASNs and UAs; ranges and countries cannot be measured), the expiry, and every warning. Then it asks `Apply? [y/N]` once.

Guard rails:

| Never blocked | How |
|---|---|
| Cloudflare's IP ranges | Fetched live, with a built-in fallback copy |
| Your origin IPs | Read from the zone's A / AAAA records; if DNS cannot be read, IP blocks are refused unless `--skip-origin-check` |
| Private, reserved and documentation ranges | Built in |
| `blocking.never_block` | Your IPs / CIDRs |
| Cloudflare's ASNs (13335, 209242) and `blocking.never_block_asns` | ASN blocks refused |

Warnings shown before confirming:

- The target carried < 1% of the last hour's excess — blocking it will not resolve the anomaly.
- A residential / mobile / backbone ASN (real users browse from it) or an ASN of unknown type.
- A whole country — the widest blast radius.
- A user agent — trivially forged and rotated.
- Choosing Block where Challenge is the default.

**Strong confirmation:** blocking (action `block`) a non-hosting ASN or any country requires retyping the ASN number or country code. `--confirm VALUE` pre-types it; `--yes` does **not** replace it.

After applying, FlareHound reads Cloudflare back to verify, writes an audit record (`block_events` in the [archive](archive.md)), and prints the undo command.

## Changing or lifting a block

- Blocking a target that is already blocked with the same action does nothing; with a different action, you must unblock it first.
- `flarehound unblock <type> <value>` asks once (`--yes` skips) and verifies by read-back.

## Expiry: `--for` and `enforce`

`--for` takes Go durations plus days: `30m`, `24h`, `7d`. Cloudflare has no native expiry, so the time is stored in the archive's audit log and **`flarehound enforce`** lifts expired blocks (recorded as `expire` events). It needs the write token and must keep running:

```bash
flarehound enforce                 # every 5 minutes (--interval), all zones
flarehound enforce --once          # one pass, e.g. from cron
```

One-click commands in alerts default to `--for 24h`. Without `--for`, a block is permanent.

## Listing and attempts

`flarehound blocks [--days 7]` lists every FlareHound block with action, mechanism, attempts over the last N days, start, expiry and reason. It reconciles Cloudflare with the audit log and flags blocks created by hand (no audit record). The daily report lists each block's attempts in its window too. Attempts come from firewall events and show "n/a" where that dataset is unavailable (Free plan). Lift a block when the attempts stop, not when it gets quiet.

## Docker

The `admin` profile in `docker-compose.yml` runs the enforcer with the write token, separate from the watchdog:

```yaml
  flarehound-admin:
    image: passport888/flarehound:latest
    profiles: ["admin"]
    restart: unless-stopped
    command: ["-config", "/app/config.json", "enforce"]
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN:-}
      CF_WRITE_TOKEN: ${CF_WRITE_TOKEN:-}
    volumes:
      - ./config.json:/app/config.json:ro
      - ./data:/app/data
```

```bash
docker compose --profile admin up -d
docker compose run --rm flarehound-admin -config /app/config.json block asn 207990 --for 24h
```

Interactive confirmation needs a TTY; `docker compose run` provides one by default.
