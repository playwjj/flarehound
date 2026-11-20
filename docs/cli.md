# Command line

```
flarehound [flags]              run the watchdog (or a one-off action)
flarehound <command> [args]     see `flarehound help`
```

## Watchdog flags

Flags go **before** a command.

| Flag | Default | Meaning |
|---|---|---|
| `-config PATH` | `config.json` | Config file. |
| `-once` | off | Run one intraday check for every zone, then exit. |
| `-daily` | off | Build the daily report now, then exit (refused if `schedule.daily_report_at` is empty). |
| `-dry-run` | off | Print messages to stdout instead of sending them; writes no state and no alert history, so it never consumes a window. |
| `-backfill N` | `0` | Archive the last N days (1–30) of hourly windows from Cloudflare, then exit. Needs the archive. |
| `-version` | off | Print the version and exit. |

Without `-once`, `-daily` or `-backfill`, FlareHound runs continuously: it checks the newest settled window immediately, then runs the intraday watch and the daily report on schedule. Each round has a 15-minute timeout and starts by re-sending queued notifications. `SIGINT` / `SIGTERM` shut it down cleanly.

```bash
flarehound -config config.json
flarehound -config config.json -once -dry-run
flarehound -config config.json -daily -dry-run
flarehound -config config.json -backfill 28
```

## Commands

| Command | Token | Page |
|---|---|---|
| `doctor` | read (+ write, to test it) | Self-check — see below |
| `health [--file heartbeat] [--max-age D]` | — | Exit 0 if the heartbeat is fresh ([heartbeat](channels.md#heartbeat-dead-man-switch)) |
| `audit` | read | [WAF audit](audit.md) |
| `calibrate [--days 7]` | read | [Calibration](archive.md#calibration) |
| `simulate --expr EXPR [--action block|challenge] [--days 7|1] [--date YYYY-MM-DD] [--before N] [--json]` | read | [Rule simulator](simulator.md) — replay a draft rule against recent traffic; changes nothing |
| `block <ip|asn|country|ua> <value> […]` | write | [Blocking](blocking.md) |
| `unblock <ip|asn|country|ua> <value> [--yes]` | write | [Blocking](blocking.md) |
| `blocks [--days 7]` | write | [Blocking](blocking.md#listing-and-attempts) |
| `enforce [--once] [--interval 5m]` | write | [Blocking](blocking.md#expiry-for-and-enforce) |
| `rules list|add|edit|delete|move|backups|restore|log` | write | [Rule changes](rules.md) |
| `ratelimit add` | write | [Rule changes](rules.md) |
| `cache add` | write | [Rule changes](rules.md) |
| `console [--listen ADDR]` | read (+ write, optional) | Serve the [web console](console.md); `--listen` overrides `console.listen` |
| `console init-admin --user NAME [--email ADDR]` | — | Create an admin account (password from the terminal or `FLAREHOUND_ADMIN_PASSWORD`) |
| `console users` | — | List console accounts |
| `console reset-password --user NAME` | — | New password, unlock, end all sessions (local recovery) |
| `console reset-totp --user NAME` | — | Turn off two-factor sign-in for an account (local recovery) |
| `geoip update [-o PATH]` | — | Download the newest DB-IP country library for [IP location](configuration.md#geoip) and replace it atomically (`-o` writes elsewhere; needs no config token) |
| `help` | — | Print command usage |

### `flarehound doctor`

Run it first after installing. It prints, read-only:

- the version and whether the configuration validates; configured channels; whether a heartbeat URL is set;
- per zone: analytics reachable (with the last hour's request count), the plan's capabilities (ASN breakdown, firewall events and how long they are kept), Worker metrics;
- a **capability matrix** — hourly watch, WAF audit, rule simulator (ASN dimension, country, referer host, firewall events for net new, rule position, `$lists`), calibration, one-click blocking, rule changes, cache rules — each ✓ or ✗ **with the missing permission named**;
- the last evaluated window, any open anomaly, the next hourly round and daily report, the heartbeat age, the archive span, the measured samples behind each newer metric's baseline (and how many days a line still accumulating has to go), and pending outbox messages;
- **storage**: what the data directory holds — `archive.db` (and its WAL) with the oldest hourly snapshot and whether large prunes return space to the disk, `console.db`, the JSONL file and its rotated copies, the `charts/` PNGs (count, size, oldest) — so a slow build-up is visible;
- the [IP location](configuration.md#geoip) library: loaded (type, build date, file date, networks), not found (the feature is off — not a problem), or present but unusable (✗).

Exit code 1 when something required is missing. Write permissions are probed with read-only calls, so an edit right is only proven by a real change.

Positional arguments come first, flags after them: `flarehound block asn 207990 --for 24h`. `-config` may be given before the command or among its flags.

## Command flags

| Flag | Default | Used by | Meaning |
|---|---|---|---|
| `--config PATH` | `config.json` | all | Config file. |
| `--zone NAME|ID` | — | all | Zone to act on. Required for `block`, `unblock`, `blocks`, `rules`, `ratelimit`, `cache` when several zones are configured; `audit` and `calibrate` default to all zones; `enforce` always covers all zones. |
| `--action ACTION` | per target / see right | `block`, `rules`, `ratelimit` | `block`: `block` or `challenge` (default `block` for ip/ua, `challenge` for asn/country). `rules add/edit`: a Cloudflare action. `ratelimit add`: default `managed_challenge`. |
| `--for DURATION` | permanent | `block` | Temporary block, e.g. `30m`, `24h`, `7d`. Needs the archive. |
| `--reason TEXT` | — | `block`, `unblock` | Kept in the audit log. |
| `--yes` | off | `block`, `unblock` | Skip the y/N prompt. Does not replace strong confirmation. Rejected by `rules`, `ratelimit`, `cache`. |
| `--confirm VALUE` | — | `block` | Pre-typed ASN / country code for strong confirmation. |
| `--skip-origin-check` | off | `block` | Block an IP even if DNS cannot be read to protect origin IPs. |
| `--days N` | `7` | `blocks`, `calibrate` | Attempt window for `blocks`; days to measure for `calibrate` (1–365). |
| `--once` | off | `enforce` | One pass, then exit. |
| `--interval DURATION` | `5m` | `enforce` | Time between passes. |
| `--phase NAME` | `custom` | `rules` | `custom`, `ratelimit` or `cache`. |
| `--expr EXPR` | — | `rules`, `ratelimit`, `cache` | Rule expression (Cloudflare rules language). |
| `--desc TEXT` | — | `rules`, `ratelimit`, `cache` | Rule description (required for `rules add`). |
| `--before N|ID` | — | `rules add/move`, `ratelimit add`, `cache add` | Place before rule N (position) or ID. |
| `--last` | off | `rules move` | Move to the end. |
| `--disabled` | off | `rules add` | Create the rule disabled. |
| `--enabled true|false` | — | `rules edit` | Enable or disable. |
| `--path PATTERN` | — | `ratelimit add`, `cache add`, `rules add` | Path pattern with `*` wildcard, turned into an expression when `--expr` is not given. |
| `--requests N` | `20` | `ratelimit add` | Requests per period per IP. |
| `--period SECONDS` | `10` | `ratelimit add` | Counting period. |
| `--timeout SECONDS` | `10` | `ratelimit add` | Mitigation timeout. |
| `--ttl DURATION` | `1d` | `cache add` | Edge TTL. |
| `--observe DURATION` | off | `rules`, `ratelimit` | After a change, watch the rule's firewall events for this long. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error, or the confirmation was declined (`aborted, nothing changed`) |
| 2 | Usage error (unknown command, bad flags or arguments) |
