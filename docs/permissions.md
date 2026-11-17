# API tokens & permissions

FlareHound uses **two separate tokens**. The watchdog holds only the read token; the write token is read only by the blocking and rule-change commands (`block`, `unblock`, `blocks`, `enforce`, `rules`, `ratelimit`, `cache`).

Create both at *Cloudflare Dashboard → My Profile → API Tokens → Create Token → Custom token*. Scope zone permissions to the zones you configure.

!!! note "Permission names"
    Cloudflare now grants custom rules **and** IP Access Rules through **Zone → WAF** (Read / Edit). **Firewall Services** is only the legacy name of the IP Access Rules permission on older accounts and cannot be granted on newer ones. Use Zone → WAF wherever it exists.

## Read token (`CF_API_TOKEN`)

| Permission | Needed for | Required? |
|---|---|---|
| Zone → **Analytics: Read** | Everything the watchdog measures (GraphQL Analytics, including the capability probe) | **Yes — the minimum** |
| Account → **Account Analytics: Read** | Worker invocations and CPU P50 (`workersInvocationsAdaptive` is an account-level dataset) | Only when a zone lists `workers` |
| Zone → **WAF: Read** | WAF audit: reading custom rules and the IP Access Rules allow-list; rule names in reports; the per-round ruleset version check | For the [WAF audit](audit.md) |
| Zone → **Zone: Read** | The plan, for the audit's quota check | Optional |

The read-token minimum was derived from the code's call sites: the watchdog's measurements are GraphQL Analytics queries only (`api.cloudflare.com/client/v4/graphql`). The one exception is the WAF audit: when it is enabled and the token has Zone → WAF: Read, each hourly round also reads the custom-rules ruleset version over REST (without that permission the call fails quietly and the audit reports "not available"). Older versions of the README also asked for Logs, Zone and Workers Scripts read access, which no code path uses. To check your own token, create one with only Zone → Analytics: Read and run `flarehound -once -dry-run`.

Without WAF: Read, the audit shows as unavailable with the reason and the watch continues unaffected.

The variable name is configurable with `cloudflare.api_token_env` (default `CF_API_TOKEN`). FlareHound refuses to start if it is empty.

## Write token (`CF_WRITE_TOKEN`)

Never merge it into the read token; the watchdog process never reads it.

| Permission | Needed for |
|---|---|
| Account → **Account Filter Lists: Edit** | The IP list `flarehound_block` used for IP blocks |
| Zone → **WAF: Edit** | Custom rules (blocks, `rules`), rate-limit rules (`ratelimit`), and the IP Access Rules fallback (older accounts: *Firewall Services: Edit*) |
| Zone → **DNS: Read** | Reading your A / AAAA records so your origin IPs are never blocked |
| Zone → **Zone: Read** | Reading the plan to check rule quotas |
| Zone → **Cache Rules: Edit** | Only for `flarehound cache add` and cache-phase changes |

The variable name is configurable with `blocking.write_token_env` (default `CF_WRITE_TOKEN`) and must differ from `cloudflare.api_token_env`.

What happens when a write permission is missing:

- **No Account Filter Lists** (or no `cloudflare.account_id` configured): IP blocks use an expression rule instead of the list — still one custom rule.
- **No access to IP Access Rules**: the fallback for a full custom-rule quota is unavailable; the plan says so.
- **No DNS: Read**: IP blocks are refused, because the origin guard cannot run — unless you pass `--skip-origin-check`.
- **No Cache Rules: Edit**: cache-phase commands fail and name the missing permission.

## How tokens are handled

- Tokens and channel secrets are read only from environment variables, never from the config file.
- All log output goes through a redacting writer: loaded secret values, `Bearer …` strings and Telegram `/bot<token>` segments are replaced with `[REDACTED]`.
- Error messages from notification channels never include the endpoint URL (webhook URLs embed secrets).
- Outbound connections go only to `api.cloudflare.com` and the notification endpoints you configure. There is no telemetry.
