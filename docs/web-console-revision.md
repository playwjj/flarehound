# Revision note: from a notification tool to a web console

> Status: direction confirmed (2026-11-18), delivered in phases since v1.3; revised the same day: the console has built-in accounts (see §5.2). v1.3 (read-only console + accounts), v1.4 (blocking from the console, undo, before/after comparison, read-only snapshots), v1.5 (Google / GitHub sign-in) and v1.7 (live hour, movers drill-down, WAF basics and rule recipes, rule management in the console) have shipped; implementation conventions are in SPEC section 19.
> This is a direction document: it describes the changes in product positioning, feature scope and security model. Implementation details are added to the corresponding SPEC sections during development.

## 1. Why change

Real-world feedback on v1.x was clear: **the notifications just read the numbers out loud, and people still did not know "what is actually going on right now".**

- Alert text is one-way and one-shot. After receiving "total +47%", what you really want to ask is: who is up? Who is down? Any new faces? Is the growth in the expensive part (origin fetches / dynamic)? Answering any of that means getting to a computer, querying the API and stitching data together.
- Handling an incident (the scraping flood of 2026-11-17, for example) is essentially a "watch the board + decide" process lasting hours: look at how the composition changes every hour, decide whether to block, whom to block, and whether the block worked. Text notifications cannot carry that process — it takes back-and-forth questions, and those questions are in fact a fixed set of queries.
- Blocking is CLI-only so far. During an incident you are next to your phone, and `flarehound block asn …` is a long way off.

Conclusion: **notifications should be the alerting layer, not the product itself.** The product itself should be a web console that shows the situation clearly whenever you open it and lets you act on the spot; notifications bring you to the console — the finishing touch, not the whole picture.

## 2. Why the Cloudflare dashboard cannot answer this

This is not FlareHound reinventing the wheel — Cloudflare's own products really have no such view:

- Dashboard analytics are split by product: domain analytics, firewall events and Workers analytics each live in their own place; "what happened across the whole site in one hour" has to be pieced together across pages by hand.
- The dashboard only has "current value" and Top N, no **baseline comparison**: there is no "28-day same-hour median" reference, so "it went up" relies on human memory.
- The dashboard has no concept of **new faces**: whether a UA / ASN is appearing for the first time, and when it arrived, is not recorded and cannot be looked up (this is exactly why the local archive exists).
- Still less does the dashboard string "detect → judge → block → verify the effect" into one path of action.

FlareHound's data layer (GraphQL + local archive + baselines) was built to answer exactly these questions; all that is missing is an interface to look at.

## 3. New positioning

**FlareHound = a self-hosted Cloudflare traffic console: live queries + baseline comparison + one-click blocking, with notifications as its alerting layer.**

Unchanged bottom lines:

- Self-hosted, single binary, tokens never leave the machine;
- The watch is always read-only;
- Every write operation has guard rails, confirmation, audit and rollback (all the rules of SPEC §13 carry over).

## 4. Web console features

### 4.1 Overview (home page)

- The current hour vs the baseline (28-day same-hour median) on one screen: total, Worker invocations, CPU P50, dynamic, origin 5xx, each with its change and a status colour.
- Switching between zones; data freshness (time of the last successful query) shown explicitly — stale data does not pretend to be live.

### 4.2 Movers (up / down)

- Across three dimensions — UA, ASN and path — the entries with the **largest rise** and the **largest fall** this hour relative to the baseline, ranked by absolute change (avoiding percentage noise on small bases), each with current volume, baseline volume, change, and its main paths / main status codes.
- This is the "visual version" of the daily report and intraday alerts: one line in a notification is a drillable ranking here.
- Measurement limit: the archive keeps only the Top N of each dimension. If an entry never made the Top N during the baseline period, its baseline is recorded as "not ranked (< the volume of rank N)" rather than 0, and the page says so — so "no record" is not misread as "surged from zero".

### 4.3 New faces

- A list of first-seen UAs / ASNs / paths: first-seen time, current volume, growth rate, main destinations.
- The data comes from the face history in the local archive (Cloudflare has no such data); known faces (the known_faces config) are marked automatically and do not raise the alarm again.
- Note: archives from v1.2 and earlier record faces only in two dimensions, UA and ASN; **the path dimension is recorded from v1.3 on**, history cannot be backfilled, and the page marks path faces "recorded since …".

### 4.4 History and timeline

- Hourly history (any period within the archive's retention), overlaid on the baseline band;
- Timeline markers: alerts, blocks / unblocks, rule changes, audit results — the effect of an action (how the volume moves after a block) can be seen right on the chart.

### 4.5 WAF audit page

- A visual version of the existing `flarehound audit`: rule list and hit counts, two-level coverage verdicts (challenge level / block level), uncovered sensitive paths, IP Access check results, each item with the same measurement notes as the CLI version.

### 4.6 Blocking

- Current block list: target, type (IP / CIDR / ASN / country / UA), action (Block / Managed Challenge), expiry, cumulative blocked attempts; supports unblocking and renewing.
- New block: one click carries the target over from a movers / new-faces entry; choose action and duration; **before applying, run the §13 guard-rail checks and show the results** (never-block list, a "blocking it will not help" hint when the share is < 1%, a strong warning for backbone / eyeball (broadband) ASNs, the real-user composition shown first for a country block); apply after a second confirmation, verify by read-back afterwards, and write the result to the audit log.
- **Automatic before/after comparison**: every block, once in effect, is marked on the timeline automatically, with a comparison of the hour before and the hour after (the target's request volume, share, and change in status-code composition) — whether the action worked is obvious at a glance, no more manual arithmetic.
- **An explicit undo entry**: each block record has "undo this action", rolling back to the state before the block in one click (fulfilling the rollback requirement of §13); undo also goes through the confirmation flow and is written to the audit log.
- Expiry handling (the job of `enforce`) is visible and traceable in the console.

### 4.7 Read-only snapshot sharing

- Any view (overview / movers / history of a given hour) can be exported as a **read-only static snapshot** (self-contained HTML, consistent with the no-external-resources principle in §6), or as a signed, time-limited temporary link;
- The purpose is incident reviews and external communication: send the situation at the time to a site team / partner without opening an account for them;
- A snapshot contains only the data at the moment of export, no tokens or account information; temporary links stop working when they expire and can be revoked at any time.

## 5. Security model: two-process isolation and accounts (the hard constraint of this revision)

The web being able to block means "write capability" enters a long-running service for the first time — this is the one point in the whole revision that must not be vague. The existing security model is: **the watch daemon never touches the write token; the write token exists only in the environment of one-off block / unblock / enforce processes.** This is not relaxed by the revision; it is implemented through isolation:

### 5.1 Two-process isolation

- **Two processes, two tokens**: `flarehound` (watch) stays read-only as before and still does not read the write token's environment variable; the web console is a separate mode, `flarehound console`, and the write token is injected only into the console process's environment. If the watch goes down, viewing is unaffected; if the console is not running, monitoring is unaffected.
- **Off by default, bound to localhost by default**: the console is not enabled by default; when enabled it listens on `127.0.0.1` by default. The tool does **not** expose itself to the public internet and does not terminate TLS; remote access is the user's own Tailscale / reverse proxy / Cloudflare Tunnel — this is the trust boundary of a self-hosted tool, stated explicitly in the docs.
- **Write operations cannot bypass the confirmation flow**: there is no "one click blocks immediately" path; the guard-rail results and the confirmation step are part of the execution chain, validated on both front end and back end, not merely greyed out in the UI.
- **Audit first**: every write operation is first written to the audit log (including the operator's account, source IP, target and guard-rail results), then executed, then verified by read-back; failures leave a trace too.
- `doctor` is extended accordingly: it checks whether the console is enabled, whether the listen address goes beyond localhost, and whether the write token has been injected into the watch process's environment by mistake (warning if found).

### 5.2 Accounts and authentication (built into the console)

For general applicability, the console has built-in accounts. Design principle: **the local account is the identity anchor; third-party sign-in is an external identity attached to the anchor** — with the anchor in place, adding quick sign-in through Google / GitHub etc. is an incremental binding, with no migration of user data.

- **Accounts and roles**: a users table (username / e-mail, password hash, role, status); only two roles: `admin` (can perform write operations such as blocking) and `viewer` (read-only browsing). No finer-grained RBAC.
- **No self-service registration**: the first admin is created at initialisation (CLI `flarehound console init-admin` or a first-start wizard); other accounts are created by an admin, or join via an invitation link issued by an admin. Self-hosted deployments have no need for strangers to register; open registration would only hand out attack surface.
- **Passwords and sessions**: passwords are stored as argon2id hashes, never in plain text; sessions are server-side and revocable, with HttpOnly / SameSite cookies, plus Secure when accessed over HTTPS (direct TLS or a trusted proxy marking `X-Forwarded-Proto: https`); on plain HTTP from a non-local source, both the console pages and `doctor` show a warning; failed sign-ins are rate-limited with temporary lockout; changing passwords, revoking all sessions and disabling accounts are basic admin operations; all write endpoints have CSRF protection.
- **Two-factor sign-in**: every account can enable TOTP two-factor sign-in (standard authenticator apps); an admin can require it globally. Accounts with TOTP enabled must pass a step-up (enter a code again) before sensitive operations such as blocking are allowed.
- **Password recovery**: via an admin reset, or an e-mailed reset link (reusing the existing SMTP notification config); no SMS recovery.
- **Third-party sign-in (extension path, see §7 v1.5)**: an external-identities table (provider + provider-side unique ID ↔ local user ID) separate from the users table, reserved from v1.3 on. Google, GitHub and other OAuth / OIDC sign-ins bind to existing local accounts as **additional sign-in methods**, not replacing local accounts; adding a sign-in method = adding a provider adapter, with zero migration of user data.
- **Works alongside external authentication, not instead of it**: when deployed behind Cloudflare Access / an authenticating reverse proxy, a "trust proxy headers" mode can be turned on that reads the operator's identity from the identity header injected by the proxy and writes it to the audit log; in this mode the console's built-in sign-in can be turned off. **This mode requires an allow-list of trusted proxy source addresses** (`trusted_proxies`): only requests from allow-listed addresses have the identity header read; otherwise anyone who can reach the port could forge an identity. Without the allow-list the mode refuses to turn on. Users pick one or combine both according to their deployment; the product does not force a choice.
- **Audit with the account as the operator (the correctness payoff of accounts)**: audit records of WAF write operations (block / unblock etc.) name the signed-in account as operator, not a source IP standing in for identity — who, when, on which target, the guard-rail verdict, the result: one accountable chain. When staff change, disabling one account cuts off their ability to act, with no need for everyone to change a shared password. In a shared-password model the audit can only record an IP, and neither accountability nor separation of duties is possible — which is exactly why WAF operations must be recorded against accounts.

## 6. Technical approach

- Still a single Go binary; the console is a subcommand / mode of the same binary, with no second runtime.
- Server-side rendering + inline SVG charts (v1.2's `internal/chart` outputs PNG and its bitmap font has no CJK; the console has its own lightweight SVG renderer that reuses its tick algorithm and colours), **no front-end build chain, no CDN, no external static resources** — usable offline, zero supply-chain surface, in keeping with "tokens never leave the machine".
- Data sources: the local SQLite archive (history, baselines, faces) + on-demand live GraphQL queries (current hour); the measurement is exactly the same as for alerts (the same calibration parameters), so the "one number on the dashboard, another in the notification" problem cannot happen.
- Pages refresh automatically (configurable interval), but every number is labelled with its window and settled state; hours that have not settled are marked "data not settled".
- **Mobile first**: notifications arrive on a phone, so the console's first screen (overview + movers) is designed first for a phone in portrait — key numbers readable at a glance, and key actions such as blocking can be completed end to end on a phone; a wide desktop screen is an enhancement, not the default assumption.

## 7. Phases

### v1.3 — Read-only console + accounts

- Overview, movers, new faces, history timeline, WAF audit page, block list (read-only);
- Console accounts land at the same time (local accounts, two roles admin / viewer, TOTP two-factor sign-in, see §5.2) — as soon as the console can be reached from beyond the local machine, sign-in is a necessity and cannot wait for v1.4;
- Notification messages can carry console deep links (only when a console base URL is configured);
- At this stage the console process holds no write token and is purely read-only, like the watch.

### v1.4 — Blocking from the console

- Two-process isolation lands; the write token goes only into the console process;
- The full set of block / unblock / renew operations with the guard-rail confirmation flow (step-up for TOTP accounts);
- Automatic before/after comparison and the undo entry (§4.6); read-only snapshots and signed temporary links (§4.7);
- The CLI's `block` / `unblock` / `blocks` / `enforce` are **kept, not removed**: headless environments and scripting still need them, and the CLI is the fallback for acting when the console fails.

### v1.5 — Third-party sign-in

- Google and GitHub OAuth sign-in (external identities bound to local accounts, see §5.2);
- Other OIDC providers to be evaluated depending on feedback.

## 8. What we will not do

- No hosted SaaS; no open self-service registration and no fine-grained RBAC (accounts are created / invited by an admin, only two roles admin / viewer, see §5.2);
- No built-in public exposure, domain or certificate management;
- No attempt to replicate every feature of the Cloudflare dashboard — only the one line of "see the situation clearly + act on the spot";
- The AI interpretation (SPEC §17) keeps its original positioning: optional, off by default, read-only evidence pack; it does not enter the decision chain just because there is now a web interface.

## 9. Impact on existing docs

- SPEC gets a new chapter "Web console" (positioning, pages, isolation model, authentication and confirmation flow);
- SPEC §13 adds the console entry point and the isolation requirement that "the write token goes only into the console process";
- The notification chapter adds the deep-link convention;
- README's one-line positioning changes from "watchdog" to "console + watchdog", and the quick start adds how to enable the console.
