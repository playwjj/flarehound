# 检测 {#detection}

FlareHound 的检测是确定性的：同样的两个窗口，永远得出同样的发现。检测链路中没有 AI。

## 窗口与调度 {#windows-and-schedule}

- **小时级看守**——在每个间隔边界之后 `schedule.intraday_offset`（默认 7 分钟），FlareHound 把**最近一个完整的整点窗口**（默认一小时）与**昨日同一窗口**对比。状态文件记录最近评估过的窗口，因此重启不会把同一窗口评估两次。启动时会立即补上最新一个已落定的窗口。
- **日报**——在 `schedule.daily_report_at`（默认 08:00，按 `schedule.timezone`）：过去 24 小时对比此前 24 小时。见 [报告](reports.md#daily-report)。
- **多个 zone** 并行检查，同时最多 `schedule.max_parallel_zones` 个（默认 4），每个 zone 有自己的状态文件。

## 测量什么 {#what-is-measured}

每个窗口、每个 zone（Cloudflare GraphQL Analytics，`httpRequestsAdaptiveGroups` 与 `workersInvocationsAdaptive`）：

1. zone 请求数（总量）。
2. `cacheStatus = "dynamic"` 的请求——昂贵的、未缓存的那部分。
3. 源站 5xx（`originResponseStatus` 500–599），按状态码（502 / 503 / 504 …）拆分，并计算其占源站应答请求的比例。
4. **源站不可达**——边缘自己给出的 52x 应答（`edgeResponseStatus` 520–526 和 530）：Cloudflare 根本连不上源站（521 拒绝连接，522/524 超时，523 无路由，525/526 TLS）。源站什么也没应答，所以这些永远不会出现在源站 5xx 里。
5. **源站延迟**——首字节时间 P95（`originResponseHeaderReceiveDurationMs`：应用计算耗时）与完整响应时间 P95（`originResponseDurationMs`：再加上传输），TCP/TLS 建连 P95 作为细节。只按源站实际应答的请求计算（`originResponseStatus > 0`）；缓存命中会把分位数拉到 0。所有套餐（含 Free）都可用；API 不应答时，延迟记为「未测量」，本轮照常进行。
6. 每个已配置的 Worker：调用量与 CPU P50 / P99（一次查询）。
7. Top UA 与 Top ASN——当前窗口取 Top 10，基线取 Top 25（「老面孔」）。
8. 每条 `path_rules`：匹配该路径的请求数（可选只计 `dynamic`）。

## 告警线 {#alert-lines}

越过任何一条线，zone 即进入异常。默认值如下（均可在 [`thresholds`](configuration.md#thresholds) 下配置）：

| 规则 | 触发条件 | 默认 |
|---|---|---|
| `total_up` | zone 请求数上涨 ≥ `total_up_pct`，且当前窗口 ≥ `min_count` | +35% |
| `dynamic_up` | dynamic 响应上涨 ≥ `dynamic_up_pct`，当前 ≥ `min_count` | +50% |
| `worker_calls_up` | 某个 Worker 的调用量上涨 ≥ `worker_calls_up_pct`，当前 ≥ `min_count` | +35% |
| `cpu_p50_up` | 某个 Worker 的 CPU P50 上涨 ≥ `cpu_p50_up_pct`；两个窗口的调用量都 ≥ `min_count`。该行附带 P50、P99 与调用量的变化及其解读（见下文） | +25% |
| `origin_5xx` | 源站 5xx > `origin_5xx_min` **且** ≥ 基线的 `origin_5xx_multiplier` 倍 | 3 倍且 > 50 |
| `origin_unreachable` | 边缘 52x ≥ `unreachable_min` **且** ≥ 基线的 2 倍（通常为 0）。若存在 522/524 记账底量（Worker zone）：≥ 底量的 3 倍、其他 52x 状态码上升，或源站不再应答——见下文 | ≥ 10 |
| `origin_slow` | 源站首字节 P95 上涨 ≥ `origin_slow_up_pct` **且** 达到 `origin_slow_min_ms`；两个窗口的源站应答请求都 ≥ 100。报告为 `ttfb`——若只有完整响应变慢（传输：大响应体、带宽），则报告为 `total` | +100% 且 ≥ 1 秒 |
| `collapse_total` / `collapse_worker` | 请求数 / 调用量下跌 ≥ `collapse_down_pct`，基线 ≥ `min_count` | −50% |
| `new_face_ua` / `new_face_asn` | 某个 UA / ASN 出现在当前 Top 10 中、不在基线 Top 25 中，且请求数超过 `new_face_min_count` | > 5,000 |
| `path_up` | 某条 `path_rules` 路径上涨 ≥ 其 `up_pct`，当前 ≥ 其 `min_count` | +100%，≥ 20 |

### 源站视角：Worker 站点与 VPS 站点 {#origin-view-worker-sites-and-vps-sites}

同样一波洪水，对 Worker 站点来说花的是钱（平台吸收了它，账单随后到），对藏在代理后面的单台 VPS 站点来说丢的是可用性（PHP worker 被占满，站点宕掉）。对 VPS 而言，最早的症状是源站变慢——比第一个 5xx 早几个小时——而出现 52x 就意味着已经宕了。这两条线都是高严重度；它们的假设会区分*未缓存负载增加导致变慢*（dynamic 或总量上涨、新面孔）与*负载持平却变慢*（应用、数据库、机器本身），并区分*首字节*与*传输*。

FlareHound 只看得到边缘：VPS 上的数据库锁、磁盘满或内存压力，只能通过它们对这些数字的影响间接看到。adaptive 数据是抽样的——适合看趋势和告警，不适合做 SLA 核算。

`min_count`（默认 1,000）之所以存在，是因为在小站点上 10 → 40 次请求就是 +300%；没有下限，就不可能安静地告警。

### 边缘 52x：故障还是记账？ {#edge-52x-outage-or-bookkeeping}

在 Worker zone 上，adaptive 数据集会把 Cache API 条目记成边缘状态码；这类条目上的边缘超时读作 522/524。于是每小时几百个这样的记录只是底量，站点其实一切正常。告警线、控制台卡片和报告共用同一个判断：

- **记账底量**——基线中的 52x ≥ 90% 是 522/524，且本窗口没有偏离它：不告警，卡片显示中性（*边缘 52x（记账底量）*），报告中出现一行「判别：记账底量」。
- 偏离这种底量——量达到底量的 ≥ 3 倍（且至少多出 `unreachable_min`）、其他状态码（521、523、530 …）占 ≥ 10% 且 ≥ `unreachable_min`，或源站应答请求低于基线的一半：该线触发，并附状态码拆分和原因。
- 其他任何基线（通常为零，或以其他状态码为主）沿用普通规则。

v1.15 之前归档的小时没有测量 52x；长基线会跳过这些小时，而不是把它们当作零。

### 新指标：基线成熟度 {#new-metrics-baseline-maturity}

一条按归档同时段中位数判断的线，好坏取决于背后实测过的小时数。指标刚上线时（52x 和源站延迟自 v1.15 起，CPU P99 自 v1.16 起），归档里有好几周的小时从未测过它：中位数只靠一两个小时，甚至一个都没有，任何普通的小时都能越线。因此，每条这样的线都会统计其基线背后**实测过的**同时段样本数（之前各天的同一小时；实测为 0 算数，没有测该指标的小时不算）：

- 少于 `thresholds.baseline_min_samples`（默认 3）：**未成熟**。`origin_unreachable`（普通规则和记账规则）与 `origin_slow` 不触发，即使只有昨日同时段能做判断也一样；看守会把该发现记为暂缓。CPU 判别把未成熟的 P99 视为未测量。控制台卡片显示*基线积累中（同时段已测 N/3 天）*，中性；指标开始采集后的第一份日报会说明一次；`doctor` 按 zone 列出计数。
- 此后该线按上述规则判断，无需人工操作。
- 仅含未成熟线却已被归档的告警（由旧版本发出）在控制台中不计为异常，并在时间线上如此标注。

两个实时窗口之间的对比（昨日同时段、日报的两天）不依赖归档，因而不受此门槛限制——但上述受门槛约束的线在触发前，必须先有成熟的归档基线。设为 `0` 关闭此门槛。

### Worker CPU：变贵了，还是构成变了？ {#worker-cpu-more-expensive-or-a-different-mix}

中位数可以在没有任何一次调用变慢的情况下上涨：一波廉价调用退去后，剩下的是较重的调用。因此每条 CPU 线都附带 **P50、P99 与调用量**，并据此解读：

- P50 和 P99 一起上涨，调用量没有下降（不低于 −10%）：**确实变贵了**——代码变更、依赖变慢、请求变重。高严重度。
- P50 上涨、P99 涨幅不到其一半、调用量下降 ≥ 10%：**构成变化**——照常报告，但为**低严重度**，并附专门的假设。
- 其他情况，或某个窗口没有 P99（v1.16 之前归档的小时）：无法判定；沿用之前的解读。

### 骤降需要已落定的数据 {#collapse-needs-settled-data}

分析数据还在写入时，新鲜窗口会被少算。当某一轮出现骤降时，FlareHound 会等待 `schedule.settle_delay`（默认 3 分钟）后重读该窗口。如果计数增长超过 2%，说明数据仍在到达：本轮暂不报这个骤降，并记为「数据未落定」。

### 长基线 {#long-baseline}

一旦 [归档](archive.md) 中有至少 20 个来自最近 28 天的同时段样本，量类发现（请求、dynamic、5xx、Worker、CPU、骤降、路径）就必须同时越过相对昨日的线**和**相对这些样本按指标计算的中位数的线。单单一个反常的昨天不会再把你叫醒。新面孔发现不受此检查约束。告警会显示长基线的数值和样本数。

## 新面孔与爬虫核验 {#new-faces-and-crawler-verification}

正规爬虫会更换 UA 版本字符串，看起来就像「新的」。一个自称是已知爬虫的新 UA，在被排除之前要先经过核验：

| 爬虫 | UA 标识包括 | 自有 ASN |
|---|---|---|
| Googlebot | `googlebot`、`adsbot-google`、`mediapartners-google`、… | 15169 |
| Bingbot | `bingbot`、`adidxbot`、`bingpreview` | 8075 |
| Applebot | `applebot` | 714, 6185 |
| YandexBot | `yandexbot`、`yandex.com/bots` | 13238, 208722 |
| Baiduspider | `baiduspider` | 55967, 38365 |

FlareHound 优先使用 Cloudflare 自己的 `verifiedBotCategory`；不可用时退而使用爬虫的 ASN。当该 UA 的请求 **≥ 90%** 通过核验时，接受其声明。有数据可判却未通过的 UA 会被报告为**冒充者**——伪装的抓取器。两种方法都不可用时，什么都不排除。

把你自己的监控和服务登记在 [`known_faces`](configuration.md#known_faces) 下；它们永远不算新面孔。

## 告警纪律 {#alert-discipline}

状态机（持久化在 `state_file` 中）把发现转化为每轮最多一条消息：

| 决策 | 时机 |
|---|---|
| `alert` | 首次发现：一段异常开始。 |
| `changed` | 异常期间，出现了本段异常此前未出现过的信号。 |
| `escalate` | 某个已报告的信号在其已报峰值之上再涨 `escalation_pct`（默认 25%）。骤降永远不会升级——正在回升的数字不是变得更糟。 |
| `recovered` | 连续 `recovery_clean_rounds`（默认 2）轮没有任何发现。一行短消息；本段异常结束。 |

一个信号是规则加上其对象（Worker、路径规则、ASN）。所有新面孔 UA 共用**一个**信号，因为爬虫会轮换 UA 字符串（实际环境中一天内出现过三批）；ASN 是稳定的，所以每个新 ASN 都是一个新信号。同一段异常内，信号跌回线下后再次越线，不会重复告警。

## 套餐能力 {#plan-capabilities}

每个 zone 首次使用时，FlareHound 会探测该套餐开放哪些维度和数据集，并且从不查询不可用的字段。缺失项会记录为 `not available on this plan, degraded: …`：

- **无 `clientAsn`**（Free）：没有 ASN Top 榜，新 ASN 检测关闭，没有 ASN 建议；日报会说明这一点。
- **无 `clientASNDescription`**（Free）：网络类型只来自内置表。
- **无防火墙事件数据集**（Free）：防火墙事件与封锁尝试量显示「n/a」，绝不显示 0。
- 如果探测本身失败，FlareHound 假定一切可用，并在下一轮再次探测。

这在实际中意味着什么，见 [限制](limitations.md)。
