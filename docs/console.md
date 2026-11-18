# Web console

The console is a second process next to the watch. It reads the archive the watch writes (`data/archive.db`) and keeps its own account database (`data/console.db`). The watch never opens the account database. Background: [web console revision](web-console-revision.md).

Without the write token the console is read-only. Give the write token to the **console process only** and admins can block, unblock and change expiry from it ([Blocking from the console](#blocking-from-the-console)); the watch must never hold it, and `flarehound doctor` checks both.

## Turn it on

```json
"console": { "enabled": true }
```

Create the first admin, then start it:

```bash
flarehound -config config.json console init-admin --user you
flarehound -config config.json console
# flarehound … console listening on http://127.0.0.1:8640 (read-only)
# … or "(blocking enabled for admins)" when CF_WRITE_TOKEN is in its environment
```

If no account exists, the console also logs a one-time setup link (`/setup?token=…`) that creates the first admin and then stops working.

In Docker, `docker-compose.yml` has an optional `flarehound-console` service (profile `console`) on the same image and data volume. It listens on `0.0.0.0:8640` inside the container (`console --listen`), published to the host's loopback only:

```bash
docker compose --profile console up -d
docker compose run --rm flarehound-console console init-admin --user you
```

For in-console blocking, set `CF_CONSOLE_WRITE_TOKEN` (passed to this service as `CF_WRITE_TOKEN`) — never give the write token to the `flarehound` watch service. For Google / GitHub sign-in, set `GOOGLE_OAUTH_SECRET` / `GITHUB_OAUTH_SECRET`.

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
| **Overview** | **The last 60 minutes, live**: queried from Cloudflare with the watch's own queries (at most once a minute), ending a few minutes ago for ingestion lag and marked *not settled*, against the 28-day baseline blended from the two clock hours it spans. Below it, the newest settled hour from the archive. Each line shows its change, its alert line and a status (normal / watch / over the line); 48-hour chart with the baseline. If the live query fails, the settled hour is shown with a note. |
| **Movers** | Who is up, who is down: user agents, ASNs and uncached paths ranked by absolute change against the baseline. Tap an entry to **drill down**: its paths, status codes, cache status and the other dimension (ASNs of a user agent, user agents of an ASN), now and in the same hour yesterday, each part drillable in turn. |
| **New faces** | User agents, ASNs and paths first seen in the last 24 h / 7 / 30 days, with their current volume. Entries in `known_faces` are marked. |
| **History** | 24 h / 7 d / 30 d (or ending on a chosen date): requests and `dynamic` against a 28-day same-hour P25–P75 band, plus a timeline of alerts, recoveries, blocks, unblocks, expiries and rule changes. |
| **WAF audit** | The same audit as `flarehound audit`, cached for 30 minutes; re-run on demand (once a minute at most). |
| **Blocks** | With the write token: the blocks as Cloudflare holds them, joined with the audit log, attempts since each block, expiry, the rule quota and whether `flarehound enforce` is running; unblock, change expiry, undo, before/after. Without it: the audit log's view. |

Apart from the live hour and the drill-down, all numbers come from settled hourly windows in the archive — the same windows, queries and baseline the alerts use. The live hour uses the same queries on a rolling window; the drill-down queries Cloudflare live (it keeps about 31 days) and caches each breakdown for 10 minutes.

### Reading the movers

The archive keeps each hour's Top N per dimension. An entry that was below a list's last place in an hour has no exact count for it, so the console uses that last place as an **upper bound** and marks it with `<`:

- `< 500` as baseline: the entry was mostly not in the list; its usual volume is below about 500. The change is then computed against 500 — a conservative figure, marked `≈`.
- An entry that has dropped out of the current list is not shown as a faller "to zero"; an entry whose baseline is only an upper bound is not shown as a faller at all.

Path movers and path faces count uncached requests — the expensive part. Path history starts with v1.3.

## Blocking from the console

Admins of a console holding the write token get a **block…** link next to user agents and ASNs on the movers and new-faces pages (prefilled), and **New block** on the blocks page. Every change goes through the same steps:

1. **Form** — target, action (default: block for IP / UA, challenge for ASN / country), duration, reason.
2. **Review** — the exact change (mechanism, the rule as it will read, rule quota), the measured share of the last hour's excess, and every guard-rail warning, exactly as the CLI shows them. Protected targets (your origin, Cloudflare, `never_block`, reserved ranges) are refused here. Nothing has changed yet.
3. **Apply** — needs the review (a token bound to exactly what was reviewed and by whom, valid 15 minutes), the typed target where a block can hit real users (eyeball / unknown ASN, a country), and a fresh two-factor code for accounts with TOTP. The guard rails run again on the server: the page is never trusted.
4. **Record, change, verify** — the console audit log records the request under your account *before* Cloudflare is touched, then the outcome; the archive's block log records the operator as `console:<account>`. The change is read back from Cloudflare.

The same steps apply to **unblock** and to **change expiry** (+24 h, +7 days, +30 days or permanent).

**Undo** is on every record of the block log: it opens the review of the inverse change — unblock a block, re-block an unblock (prefilled form), restore the previous expiry — and goes through the same confirmation. Only a target's newest record can be undone.

**Before / after**: for every block, the console compares the hour before with the hour after it took effect — the target's requests and share of the zone, its status codes (blocked requests are still counted, as 403), the zone total, and the rule's attempts. It is computed automatically once that hour has settled (a partial comparison is shown before) and the block is marked on the history timeline.

**Expiry** stays the job of `flarehound enforce` (CLI, or the `admin` service in docker-compose). The blocks page shows when it last ran and warns when blocks have an expiry but the enforcer is not running.

The CLI (`flarehound block / unblock / blocks / enforce`) is unchanged and remains the fallback when the console is down.

## WAF rules

**WAF rules** lists the zone's custom and rate-limit rules in execution order, each with a plain-words explanation ("If the path starts with /login and not a Cloudflare-verified bot → managed challenge"), its action and state. It reads them with the read token (Zone → WAF: Read; Zone: Read for the quota).

With the write token, admins can also:

- **add a rule from a recipe** — the recipe catalogue explains each one; the form asks only for what it needs (paths, IPs, a secret header …);
- **enable / disable**, **move up / to the top**, **delete** a rule;
- **restore** a backup (one is taken before every change).

Every change goes through a review page — the rule in plain words, the exact change, the quota after, warnings — and is applied with the same safeguards as blocking: a review token bound to what was reviewed *and to the ruleset version it was planned on* (if someone else changed the rules meanwhile, you are asked to review again), a fresh two-factor code for accounts with TOTP, the account audit log written before Cloudflare is touched, a phase backup, read-back verification, and the execution log. FlareHound's own block rules are shown but managed on the blocks page.

The rules and the audit are kept warm in the background (rules re-read every 10 minutes, the audit re-run when 30 minutes old), so both pages open immediately; a change made in the console refreshes them, and the rules page has a refresh link. Recipes are plan-aware: a recipe whose rule type is at the plan's quota says so instead of offering a form, Free zones are not offered skip scopes they lack, and their rate-limit timing is fixed at 10 seconds.

The **WAF audit** page puts **How to fix** first — each finding with what to do and a **Fix with a recipe** link (or the CLI command) — and keeps the full report below. New to this? [WAF basics](waf-guide.md) / [中文](waf-guide-zh.md).

## Read-only snapshots

Overview, movers and history have a **Snapshot** button. It freezes the view into one self-contained HTML page — stylesheet inlined, no script, no external resource, no account data or tokens — and gives you a share link that works **without sign-in** for 24 hours, 7 or 30 days. Use it for incident reviews and to show the situation to a site team or partner without giving them an account.

The **Snapshots** page lists them (admins see all, others their own): download the HTML file, or revoke the link at any time. Creating and revoking are recorded in the account audit log. Shared pages are served with `noindex` and a strict Content-Security-Policy.

## Accounts

- **Roles**: `admin` (manages accounts; blocks when the console holds the write token) and `viewer` (reads, creates snapshots).
- **No self-sign-up**. Admins create accounts on the Users page (a temporary password is shown once; the user must change it at first sign-in) or issue a single-use invitation link (72 hours).
- **Passwords**: at least 10 characters, stored as argon2id hashes. Changing a password signs out every other session.
- **Two-factor sign-in (TOTP)**: each user can turn it on under Account — scan the QR code with any authenticator app (or type the key shown next to it). `console.require_totp` makes it mandatory. Accounts with TOTP confirm a fresh code before account administration (step-up).
- **Throttling**: 10 sign-in attempts per minute per IP; 5 consecutive failures lock an account for 15 minutes (admins can unlock).
- **Sessions** are server-side and revocable: users see and end their own; admins can sign anyone out or disable an account (which ends its sessions).
- **Audit log**: sign-ins, failures, password and 2FA changes, account administration and audit re-runs, with account and IP — on the Users page.

**Forgot your password?** With `notify.email` (the SMTP settings used for notifications) and `console.base_url` configured, the sign-in page offers a reset by e-mail: a single-use link valid for 30 minutes goes to the address on the account. The page answers the same whether or not the account exists; at most one mail per account every 10 minutes. A reset ends every session of the account and does not bypass two-factor sign-in. Without SMTP, an admin resets the password (Users page), or use the local commands below.

Local recovery (on the machine, no web sign-in needed):

```bash
flarehound console users
flarehound console reset-password --user NAME
flarehound console reset-totp --user NAME
```

### Sign in with Google or GitHub

Third-party sign-in is an **additional** way into an existing account — never a way to get one:

- Each person first signs in with their password, then links Google and/or GitHub under **Account** (re-entering the password). From then on the login page's *Sign in with Google / GitHub* works for them.
- An identity that is not linked signs in to nothing. No account is created and nothing is matched by e-mail address.
- Two-factor sign-in still applies after the provider, as do disabled accounts, forced password changes and `require_totp`. Passwords keep working.
- Users unlink from their account page; admins see every account's linked identities on the Users page and can remove them. Linking, unlinking and every sign-in are in the account audit log.

Set it up:

1. Set `console.base_url` to the HTTPS address people use (providers redirect there).
2. Create an OAuth app and register the redirect URI `<base_url>/oauth/<provider>/callback`:
    - **Google**: Google Cloud console → APIs & Services → Credentials → *OAuth client ID* (Web application). Redirect URI `https://…/oauth/google/callback`.
    - **GitHub**: Settings → Developer settings → *OAuth Apps* → New. Callback URL `https://…/oauth/github/callback`.
3. Configure the client ID, and put the secret in an environment variable of the **console** process:

```json
"console": {
  "enabled": true,
  "base_url": "https://hound.example.ts.net",
  "oauth": {
    "google": { "client_id": "1234-abc.apps.googleusercontent.com", "client_secret_env": "GOOGLE_OAUTH_SECRET" },
    "github": { "client_id": "Iv1.0123456789abcdef", "client_secret_env": "GITHUB_OAUTH_SECRET" }
  }
}
```

`flarehound doctor` prints the exact redirect URIs to register. With a provider configured, the console also connects out to that provider (Google: `accounts.google.com`, `oauth2.googleapis.com`; GitHub: `github.com`, `api.github.com`).

How it is protected: authorization-code flow with PKCE; the `state` value is single use, expires in 10 minutes and must come back to the same browser (cookie); Google's ID token is checked for issuer, audience, expiry and nonce; GitHub accounts are identified by their numeric ID (logins can be renamed).

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
- Retention: expired sessions and sign-in states are removed hourly; a snapshot's page is dropped 30 days after its link expired or was revoked (the record stays); account audit entries are kept for a year, cached before/after comparisons for 90 days.
- `console.db` is created with mode 0600 and holds password hashes and TOTP secrets — back it up like a credential store.
- `flarehound doctor` checks: console on/off, loopback-only listening, proxy settings, accounts and admins, and where the write token is: an error if the **watch** has it; for the console, whether blocking is enabled — with a warning when it is and `console.require_totp` is off.
- With the write token in the console, turn on `console.require_totp`: then every account that can change Cloudflare signs in with two factors and confirms every change with a fresh code.
