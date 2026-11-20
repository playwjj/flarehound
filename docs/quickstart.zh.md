# 快速开始 {#quick-start}

FlareHound 是单个 Go 二进制文件，以多架构 Docker 镜像（`linux/amd64`、`linux/arm64`）发布在 `passport888/flarehound`。把它运行在你自己的 VPS、家用服务器或 NAS 上——刻意不放在 Cloudflare 上，这样当它所看守的平台出问题时，看守本身没有盲区。它只需要出站 HTTPS 和一个可写的数据目录。

## 1. 创建只读 Token {#1-create-a-read-only-token}

在 *Cloudflare Dashboard → My Profile → API Tokens → Create Token → Custom token* 中，为你要看守的 zone 授予 **Zone → Analytics: Read**。如果要看守 Worker，再加 **Account → Account Analytics: Read**；WAF 规则体检需要 **Zone → WAF: Read**。详见 [API Token 与权限](permissions.md)。

## 2. 编写 `config.json` {#2-write-configjson}

从仓库复制 `config.example.json`，至少填好 zone。最小示例：

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

- `zone_id`（以及仅在 `workers` 非空时才必需的 `account_id`）必须是面板中的 32 位十六进制 ID。
- 未写出的配置项保持默认值——见 [配置参考](configuration.md)。
- 密钥永远不写进文件：文件只写出保存密钥的环境变量名。
- 请设置 `schedule.timezone`：不设置时 FlareHound 使用主机本地时间，而容器内通常是 UTC。

## 3. 启动 {#3-start-it}

仓库中的 `docker-compose.yml`：

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

容器运行 `flarehound -config /app/config.json`；状态、通知发件箱和归档都保存在 `./data` 中。如果你添加了更多渠道，也要把它们的环境变量传给容器（见 [通知渠道](channels.md)）。

## 4. 检查安装 {#4-check-the-installation}

```bash
docker compose run --rm flarehound -config /app/config.json doctor
```

它会告诉你每个 Token 能做什么——看守、体检、封锁——并指出缺少的权限。

## 5. 上线前先试运行 {#5-try-it-before-going-live}

`-dry-run` 把消息打印到标准输出，而不是发送出去：

```bash
docker compose run --rm flarehound -config /app/config.json -once -dry-run    # one hourly check
docker compose run --rm flarehound -config /app/config.json -daily -dry-run   # today's daily report
```

!!! note
    看守会在状态文件中记录最近评估过的窗口，因此 `-once` 已经评估过的窗口会被下一次运行跳过（日志中显示 `window … already evaluated, skipping`）。

## 6. 可选：立即补齐归档 {#6-optional-fill-the-archive-now}

Cloudflare 保留约 31 天的分析数据。补录最近四周的数据，可以让近 4 周同时段中位数基线从第一天就生效，而不必等到第五周：

```bash
docker compose run --rm flarehound -config /app/config.json -backfill 28
```

补录按每秒约一次查询的速度进行，每个 zone 大约需要一小时。见 [本地归档](archive.md)。

## 不使用 Docker {#without-docker}

```bash
go build -o flarehound ./cmd/flarehound
CF_API_TOKEN=... ./flarehound -config config.json
```

## 下一步 {#next-steps}

- 封锁与规则变更需要独立的写 Token 和 `admin` compose profile：[一键封锁](blocking.md)、[规则变更](rules.md)。
- 如果 FlareHound 的数字看起来比面板高，这是预期之内的：[口径校准](archive.md#calibration)。
