# Web console

!!! note "v1.3 — read-only"
    This version shows; it does not act. Blocking from the console arrives in v1.4 — until then use [`flarehound block`](blocking.md). Background: [web console revision](web-console-revision.md).

The console is a second process next to the watch. It reads the archive the watch writes (`data/archive.db`) and keeps its own account database (`data/console.db`). The watch never opens the account database, and this console version never reads the write token.

## Turn it on

```json
"console": { "enabled": true }
```

Create the first admin, then start it:

```bash
flarehound -config config.json console init-admin --user you
flarehound -config config.json console
# flarehound … console listening on http://127.0.0.1:8640 (read-only)
```

If no account exists, the console also logs a one-time setup link (`/setup?token=…`) that creates the first admin and then stops working.

In Docker, run it as a second service from the same image and data volume, **without** `CF_WRITE_TOKEN` in its environment:

```yaml
  console:
    image: passport888/flarehound:latest
    command: ["-config", "/app/config.json", "console"]
    environment:
      - CF_API_TOKEN=${CF_API_TOKEN}
    volumes:
      - ./config.json:/app/config.json:ro
      - ./data:/app/data
    ports:
      - "127.0.0.1:8640:8640"
    healthcheck:
      test: ["CMD", "flarehound", "-config", "/app/config.json", "health", "--file", "heartbeat-console", "--max-age", "15m"]
```

Inside a container, set `"listen": "0.0.0.0:8640"` and publish the port only to the host (`127.0.0.1:8640:8640`) or to your tunnel.

## Reaching it from your phone

FlareHound does no TLS and no public exposure — the console listens on `127.0.0.1` by default. Put it behind something you already trust:

- **Tailscale**: `tailscale serve --bg 8640` gives you `https://<machine>.<tailnet>.ts.net`.
- **Cloudflare Tunnel** (optionally with Cloudflare Access in front).
- **A TLS reverse proxy** (Caddy, nginx).

Then set `console.base_url` to that address and list the proxy in `console.trusted_proxies` (e.g. `"127.0.0.1"` when the proxy runs on the same machine). Only then does the console believe `X-Forwarded-For` / `X-Forwarded-Proto`, mark session cookies `Secure`, and log the real client IP. A plain-HTTP connection from another machine shows a warning on every page, and `flarehound doctor` reports it.

With `base_url` set, alerts link to the movers view, recoveries and daily reports to the overview, and ruleset-change audits to the WAF audit page.

## Pages

| Page | What it answers |
|---|---|
| **Overview** | The newest settled hour against the 28-day same-hour median: zone requests, Worker calls and CPU P50, uncached (`dynamic`), origin 5xx — each with its change, its alert line and a status (normal / watch / over the line). 48-hour chart with the baseline. A stale-data warning when the watch has not archived recently. |
| **Movers** | Who is up, who is down: user agents, ASNs and uncached paths ranked by absolute change against the baseline. |
| **New faces** | User agents, ASNs and paths first seen in the last 24 h / 7 / 30 days, with their current volume. Entries in `known_faces` are marked. |
| **History** | 24 h / 7 d / 30 d (or ending on a chosen date): requests and `dynamic` against a 28-day same-hour P25–P75 band, plus a timeline of alerts, recoveries, blocks, unblocks, expiries and rule changes. |
| **WAF audit** | The same audit as `flarehound audit`, cached for 30 minutes; re-run on demand (once a minute at most). |
| **Blocks** | Active blocks and the last 30 days of the block audit log (read-only). |

All numbers come from settled hourly windows in the archive — the same windows, calibration and baseline the alerts use. The hour in progress is not shown.

### Reading the movers

The archive keeps each hour's Top N per dimension. An entry that was below a list's last place in an hour has no exact count for it, so the console uses that last place as an **upper bound** and marks it with `<`:

- `< 500` as baseline: the entry was mostly not in the list; its usual volume is below about 500. The change is then computed against 500 — a conservative figure, marked `≈`.
- An entry that has dropped out of the current list is not shown as a faller "to zero"; an entry whose baseline is only an upper bound is not shown as a faller at all.

Path movers and path faces count uncached requests — the expensive part. Path history starts with v1.3.

## Accounts

- **Roles**: `admin` (manages accounts; from v1.4 also blocks) and `viewer` (reads).
- **No self-sign-up**. Admins create accounts on the Users page (a temporary password is shown once; the user must change it at first sign-in) or issue a single-use invitation link (72 hours).
- **Passwords**: at least 10 characters, stored as argon2id hashes. Changing a password signs out every other session.
- **Two-factor sign-in (TOTP)**: each user can turn it on under Account (any authenticator app; the key is shown for manual entry with an `otpauth://` URI). `console.require_totp` makes it mandatory. Accounts with TOTP confirm a fresh code before account administration (step-up).
- **Throttling**: 10 sign-in attempts per minute per IP; 5 consecutive failures lock an account for 15 minutes (admins can unlock).
- **Sessions** are server-side and revocable: users see and end their own; admins can sign anyone out or disable an account (which ends its sessions).
- **Audit log**: sign-ins, failures, password and 2FA changes, account administration and audit re-runs, with account and IP — on the Users page.

Local recovery (on the machine, no web sign-in needed):

```bash
flarehound console users
flarehound console reset-password --user NAME
flarehound console reset-totp --user NAME
```

### Behind an authenticating proxy

When Cloudflare Access, oauth2-proxy or similar already authenticates people, the console can take the identity from the header it injects:

```json
"console": {
  "enabled": true,
  "trusted_proxies": ["127.0.0.1"],
  "proxy_auth": { "header": "Cf-Access-Authenticated-User-Email", "default_role": "viewer" }
}
```

The header is read only from `trusted_proxies` (the config refuses `proxy_auth.header` without them). An identity matching a local account's username or e-mail acts as that account; others get `default_role` (`viewer`, or `none` to refuse). `disable_login: true` turns the password form off.

## Security notes

- No JavaScript; strict Content-Security-Policy (`default-src 'none'`); no external resources.
- Every form carries a CSRF token; cross-site POSTs are refused.
- `console.db` is created with mode 0600 and holds password hashes and TOTP secrets — back it up like a credential store.
- `flarehound doctor` checks: console on/off, loopback-only listening, proxy settings, accounts and admins, and whether the **watch** or this **console** has the write token in its environment (it must not).
