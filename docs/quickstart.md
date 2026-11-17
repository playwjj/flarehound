# Quick start

FlareHound is a single Go binary, shipped as a multi-arch Docker image (`linux/amd64`, `linux/arm64`) at `passport888/flarehound`. Run it on your own VPS, home server or NAS — deliberately not on Cloudflare, so the watchdog has no blind spot when the platform it watches is in trouble. It needs only outbound HTTPS and a writable data directory.

## 1. Create a read-only token

In *Cloudflare Dashboard → My Profile → API Tokens → Create Token → Custom token*, grant **Zone → Analytics: Read** for the zones you watch. Add **Account → Account Analytics: Read** if you watch Workers, and **Zone → WAF: Read** for the WAF audit. Details: [API tokens & permissions](permissions.md).

## 2. Write `config.json`

Copy `config.example.json` from the repository and fill in at least the zone. Minimal example:

```json
{
  "cloudflare": {
    "account_id": "0123456789abcdef0123456789abcdef",
    "zones": [
      { "name": "example.com", "zone_id": "0123456789abcdef0123456789abcdef", "workers": ["my-worker"] }
    ]
  },
  "schedule": { "timezone": "Europe/Berlin" },
  "report": { "language": "en" },
  "notify": { "webhook_url_env": "FLAREHOUND_WEBHOOK_URL" }
}
```

- `zone_id` (and `account_id`, required only when `workers` is non-empty) must be the 32-character hex IDs from the dashboard.
- Every key left out keeps its default — see the [configuration reference](configuration.md).
- Secrets never go into the file: it only names the environment variables that hold them.
- Set `schedule.timezone`: without it FlareHound uses the host's local time, which in the container is usually UTC.

## 3. Start it

`docker-compose.yml` from the repository:

```yaml
services:
  flarehound:
    image: passport888/flarehound:latest
    restart: unless-stopped
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN:?set CF_API_TOKEN to a read-only Cloudflare API token}
      FLAREHOUND_WEBHOOK_URL: ${FLAREHOUND_WEBHOOK_URL:-}
      TELEGRAM_BOT_TOKEN: ${TELEGRAM_BOT_TOKEN:-}
    volumes:
      - ./config.json:/app/config.json:ro
      - ./data:/app/data
```

```bash
export CF_API_TOKEN=...            # read-only token
export FLAREHOUND_WEBHOOK_URL=...  # or configure another channel
docker compose up -d
docker compose logs -f flarehound
```

The container runs `flarehound -config /app/config.json`; state, the notification outbox and the archive live in `./data`. If you add more channels, pass their environment variables to the container too (see [Channels](channels.md)).

## 4. Try it before going live

`-dry-run` prints messages to stdout instead of sending them:

```bash
docker compose run --rm flarehound -config /app/config.json -once -dry-run    # one hourly check
docker compose run --rm flarehound -config /app/config.json -daily -dry-run   # today's daily report
```

!!! note
    The watchdog records the last evaluated window in its state file, so a window that `-once` has already evaluated is skipped by the next run (`window … already evaluated, skipping` in the log).

## 5. Optional: fill the archive now

Cloudflare keeps about 31 days of analytics. Backfilling the last four weeks lets the 4-week median baseline work from day one instead of week five:

```bash
docker compose run --rm flarehound -config /app/config.json -backfill 28
```

It is paced at about one query per second and takes roughly an hour per zone. See [Local archive](archive.md).

## Without Docker

```bash
go build -o flarehound ./cmd/flarehound
CF_API_TOKEN=... ./flarehound -config config.json
```

## Next steps

- Blocking and rule changes need a separate write token and the `admin` compose profile: [One-click blocking](blocking.md), [Rule changes](rules.md).
- If FlareHound's numbers look higher than the dashboard's, that is expected: [Calibration](archive.md#calibration).
