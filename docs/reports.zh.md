# 告警、日报与建议 {#alerts-daily-report-suggestions}

每条消息都是纯文本，结论先行，使用英文或中文（`report.language`）。除文本外，每条消息还携带结构化字段（`kind`、`zone`、`decision`、窗口、触发的 `rules`），由 webhook 和 JSONL 渠道透传——见 [通知渠道](channels.md)。

| `kind` | 发送时机 |
|---|---|
| `intraday` | 小时级看守的决策为 `alert`、`changed`、`escalate` 或 `recovered`（[检测](detection.md#alert-discipline)） |
| `daily` | 每天 `schedule.daily_report_at` |
| `audit` | 自定义规则集发生变化，且重新体检发现了问题（[WAF 规则体检](audit.md)） |

## 小时告警 {#intraday-alert}

```
FlareHound · example.com — anomaly
Worker web calls +52.0%, Worker web CPU P50 +50.0%, dynamic +75.0%, zone requests +52.0% (+1 more)
Window 2026-11-17 08:00–09:00 (Asia/Shanghai)

Attribution:
- expensive (Worker/origin) 40,000 → 70,000 (+30,000); cheap (edge cache) 60,000 → 82,000 (+22,000)
- top dynamic paths: /rank 35,000 (was 20,000)
- AS207990 hits: /rank 35,000

Hypotheses:
- [high] Crawler/bot surge: new source AS207990 carries ~87% of the excess.
  Falsified if its path mix matches normal visitors and it comes from residential/mobile networks …

Suggestions (read-only — FlareHound never applies them; do it in the Cloudflare dashboard):
1. Block AS207990 (EXAMPLE-HOSTING-AS, hosting network)
   where: Security → WAF → Custom rules, action Block
   expression: (ip.geoip.asnum in {207990}) and not cf.client.bot
   ...
```

各部分依次为：

1. **标题行**——越过了哪些线、越过多少（最多四条；骤降、5xx、昂贵流量、总量和新面孔优先）。
2. **双窗口对比**——总量、Worker 调用量与 CPU P50 / P99、dynamic、源站 5xx（含其占源站应答的比例及 502/503/504 拆分）、源站不可达（52x，有则显示，附状态码拆分；若存在 522/524 底量，再加一行判别：记账底量，或偏离及原因）、源站延迟 P95（首字节 / 完整响应）；长基线生效时一并显示。
3. **归因拆分**——只在确实要发消息时才采集（安静的轮次不额外花查询）。归因查询失败绝不会阻塞告警。
4. **机制假设**——每条都带置信度和证伪点。没有站得住的假设时，消息会说明只报数。
5. **封锁候选**——见下文。
6. **处置建议**——见下文。恢复消息不带建议。

邮件收到的是同一份报告的 HTML 版并附图表，Telegram、Discord 和企业微信以图片形式收到图表——见 [图表与 HTML](channels.md#charts-and-html-reportvisuals-default-on)。

### 严重度：是声势大，还是真的疼？ {#severity-is-it-loud-or-does-it-hurt}

被边缘吸收的洪水——zone 请求或 Worker 调用上涨、出现新面孔，但**真实渲染（`dynamic`）涨幅低于 15%**，且 dynamic、CPU、源站 5xx、源站变慢/不可达、骤降、路径等线都没有越过——会作为单独的结论以**低严重度**报告：*「增量在边缘被吸收：真实渲染 +1.0%，CPU 与源站错误未越线——源站与 Worker 渲染无压力。观察即可，无需处置。」*Worker CPU P50 上涨若能由 P99 和调用量解释为**构成变化**（且没有其他昂贵项），同样是低严重度：*「低严重度：Worker CPU 构成变化」*。任何昂贵或出故障的情况都是**高**严重度。JSONL 记录带有 `severity: "low" | "high"`。

### 面板口径与网络标签 {#dashboard-terms-and-network-labels}

一旦 [口径校准](archive.md#calibration) 有了数据，「越线」中的每个计数都会附上面板口径的等价值——*「新 UA … 18,521 次请求（≈ 面板 9,080 次）」*——因为人们习惯用面板上的数字思考。新 ASN 会标注其注册名称和网络类型——*「AS45102 [ALIBABA-CN-NET，机房/云网络]」*——这样做决定前不用再去查（名称查询需要 `clientASNDescription` 维度；内置表不需要它也能用）。

### 贵贱分离 {#expensive-vs-cheap}

流量按 `cacheStatus` 拆分：`hit`、`stale`、`updating` 和 `revalidated` 是**廉价**的；其他一切（`dynamic`、`miss`、`bypass`、`expired`、未知值）都是**昂贵**的。真实渲染（`dynamic`）放在最前面，并与其他缓存未命中分开显示——它才是值班的人盯着的那个数字。

### 机制假设 {#hypotheses}

由固定规则产生，例如：

- 某个新面孔承担了 ≥ 80% 的增量 → 高置信度；≥ 50% → 中置信度。
- ≥ 70% 的增量落在廉价流量上 → 「廉价流量，实际成本小」。
- dynamic 上涨而总量持平 → 可缓存性下降。
- CPU 上涨而调用量持平 → 部署变更或慢路径。
- 源站 5xx，附按路径的分布；≥ 80% 集中在一条路径 → 是某个路由的缺陷，而非源站故障。
- 其他情况 → 没有集中的驱动因素，证据不足。

### 封锁候选 {#block-candidates}

- 占比是相对**增量**（当前 − 基线）计算的。没有增量就没有候选：流量持平时的 CPU、5xx 或骤降异常，绝不会建议封 IP。
- 单个 IP 承担 ≥ 5% 增量时会被列出，并附一键命令（`flarehound block ip … --for 24h`）。
- 每一行 IP——封锁候选、Top 客户端 IP、日报中被拦最多的 IP 以及 FlareHound 的封锁项——在加载了国家库时都会附上其 [归属地](configuration.md#geoip)：`106.201.104.211 [IN · India]`，或在 `report.language: zh` 时显示为 `106.201.104.211 [印度 (IN)]`。这是注册/路由所在国家，而非运营者所在国家，并且它从不改变报告的内容。
- 如果可封锁的最大 IP 承担不到 1%，来源就是**分散的**：消息会说明逐个封 IP 无济于事，并指向 ASN 或路径层面的处置。
- Cloudflare 自己的网段（通常是某个 Worker 在调用你的站点）、私有 / 保留网段以及 `blocking.never_block` 中的条目会作为「集中但不可封锁」单独列出，并注明原因。
- 自称已知爬虫却未通过核验的 UA 会被点名为**冒充者**。

## 处置建议 {#suggestions}

建议是只读的意见；每条都附有证据、预期收益、影响、回滚方式，并且——在 FlareHound 能执行的情况下——附上 [一键封锁](blocking.md) 或 [规则变更](rules.md) 模块的一键命令。每条消息最多 6 条。

| 类型 | 触发条件 | 建议 | 一键命令 |
|---|---|---|---|
| 封锁 ASN | 该 ASN 解释了 ≥ 20% 的增量，**且**是机房/云网络 | 封锁 `(ip.geoip.asnum in {N}) and not cf.client.bot` | `flarehound block asn N --action block --for 24h` |
| 质询 ASN | 同上，但为住宅/骨干网络或未知网络 | 托管质询，明确*不*封锁 | `flarehound block asn N --for 24h` |
| 质询路径 | 某条敏感路径的线被越过，或它解释了 ≥ 30% 的 dynamic 增量 | 对该路径启用托管质询 | `flarehound rules add --action managed_challenge …` |
| 限速 | 一条路径解释了 ≥ 50% 的 dynamic 增量，来源分散，且尚未被质询建议覆盖 | 按 IP，20 次请求 / 10 秒，托管质询 | `flarehound ratelimit add --path … --requests 20 --period 10` |
| 缓存 | 某条静态资源路径（js、css、图片、字体、媒体、pdf、xml、wasm …；不含 json）出现在 Top dynamic 路径中，且请求数 ≥ `min_count` | 边缘缓存规则，TTL 1 天（文件名带内容哈希时为 1 年） | `flarehound cache add --path … --ttl 1d` |
| 成本提示 | CPU 上涨而调用量持平 | 检查该 Worker 的部署记录和慢路径 | — |

证据门槛：

- 封锁、质询和限速建议至少需要一条中或高置信度的假设。
- 当 ≥ 70% 的增量是廉价的边缘流量时，不给出任何封锁类建议。
- 缓存和成本建议是结构性的，不受门槛限制。
- 敏感路径即 `path_rules` 和 `daily.paths` 中的全部模式。
- 网络类型先查内置的主要云 / 机房与宽带 / 骨干 ASN 表，再在套餐提供时根据 ASN 注册名称中的关键词判断；否则为「未知」。Cloudflare 自己的 ASN 和 `blocking.never_block_asns` 永远不会被建议。

路径模式按如下方式转换为表达式：`/x` → `http.request.uri.path eq "/x"`；`/x*` → `starts_with(http.request.uri.path, "/x")`；其他含 `*` 的模式 → `wildcard`。

## 日报 {#daily-report}

每天都发送（它是定时报告，不是告警）。第一行是「一切正常」或结论。

- 过去 24 小时对比此前 24 小时：与小时级看守相同的各条线（不经状态机）、成本拆分、Top dynamic 路径。
- Top ASN 与 UA，新出现的标记为 `[new]`（中文报告为 `[新]`）；已核验爬虫与冒充者。
- **固定检查点：**
    - 按规则统计的防火墙事件（带规则名称），以及最常被拦截或质询的 IP——在没有该数据集的套餐上显示「不可用」，绝不显示 0；
    - FlareHound 的每个封锁项及其在窗口内的尝试量、开始时间和到期时间——等尝试停止了再解封，而不是看起来安静了就解封；
    - `daily.paths`：每条路径的回源量对比其 `max`（✓ / ⚠）；
    - `daily.artifacts`：已知的记账假象，与访客错误分开计数。
- 处置建议（不含限速建议：日报没有按 IP 的数据）。
- WAF 规则体检摘要：没问题时一行，只对需要关注的项给出细节。
- 仍未结束的小时级异常，及其开始时间和信号。
- 归档状态与长基线就绪程度（积累期间附 `-backfill 28` 提示）。
- 一行 [口径校准](archive.md#calibration) 比值。
- 数据缺口：任何失败的查询都会点名，而不是悄悄报成零。

按需运行：`flarehound -daily`（加 `-dry-run` 则打印而不发送）。
