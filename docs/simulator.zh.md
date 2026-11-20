# 规则模拟器 {#rule-simulator}

封锁从来不是针对单个目标：它是一条 WAF 表达式——一组 ASN、一个国家、一个 UA 条件、一条路径，加上让已验证爬虫与自家服务免于误伤的豁免分支。表达式*实际做了什么*，并不等于目标的流量。一个真实 zone 一周内的三个例子：

- **AS30633 被高估了约 4 倍。** 每天约 14.7 万次请求，被列为封禁候选。但其中约 11.1 万是 ExaSearchBot——Cloudflare 已验证机器人，会被 `and not cf.client.bot` 豁免。规则真正能拦的只有每天约 3.6 万。
- **本该在封之前写好的豁免。** 封 AS45102 时连带拦住了 rednote（非已验证机器人，每天约 5 千次，全部来自该网络），而站长此前决定不封它。`and not (http.user_agent contains "rednote")` 分支是事后补的。
- **一条无法估算的规则。** 一个 referer 分支（「referer 恰好等于首页」）只能在上线后靠观察挑战数反推效果。

模拟器把草稿表达式拿过去几天的真实流量回放一遍，在规则存在之前给出答案。**它只读**，不创建规则，也不产生封锁方案。

## 运行 {#running-it}

```bash
flarehound simulate --zone starngage.com --expr '(ip.geoip.asnum eq 30633 and not cf.client.bot)' --action challenge
flarehound simulate --expr 'http.user_agent contains "python-requests"' --days 1
flarehound simulate --expr '…' --date 2026-11-17      # 指定某一天（本地时区）
flarehound simulate --expr '…' --json                 # 以 JSON 输出报告
```

只需读 Token（`Zone → Analytics: Read`），watch 侧即可运行。窗口：过去 **7 天**（`--days 1` 为 24 小时，`--date` 为 `schedule.timezone` 下的某一天），截止到 **1 小时前**——最近一小时的数据尚未落定。

控制台：**规则模拟** 标签页（任何已登录账号）。构成拆分的各行可下钻。

**封锁确认页自动附带模拟**：对 ASN、国家或 UA 封锁，确认页会模拟该目标将生成的规则（`(ip.geoip.asnum in {N}) and not cf.client.bot` 等），把裁决显示在确认按钮上方，取代单目标的量/占比口径。IP 封锁维持现有的轻量查询。如果表达式在该区不可评估（Free 套餐、无国家维度……），确认页回落到原有口径并说明原因。

## 报告内容 {#what-the-report-says}

1. **毛命中**——不计表达式自身 `and not …` 分支时的命中量，以及计入后的量（规则命中）；占总量与占 dynamic（回源）的百分比；按天拆分。
2. **豁免拆分**——毛命中减规则命中：「以为要拦的」与「规则实际会拦的」差多少。每个顶层 `and not …` 分支单独计数。
3. **净新增**——核心数字：规则命中减去已被现有规则拦截或挑战的部分（用同一表达式过滤防火墙事件；只计 block、challenge、JS challenge、managed challenge 的发出，不计其结果，避免重复计数）。按全规则集口径，不考虑本规则将来的插入位置。
4. **构成拆分**——Top 5 路径、UA、客户端 IP（带 [IP 归属地](configuration.md#geoip)）、国家；表达式未绑定 ASN 时给 Top 网络。命中中的已知来源（`known_faces`）单列。
5. **动作差异**——`block`：能通过挑战的真人也会被全拦。`challenge`：通过率估计暂不提供。
6. **置信标签**——每份报告一个：
    - *近似（采样数据）*；
    - *近似（含数据集拼接估计）*——净新增拼接了两套数据集；
    - *上界*——有子表达式只能放宽评估（referer，见下）；所有数字带 `≤`，并点名该子表达式。
7. **裁决行**——一句话结论，沿用护栏口径：无命中；命中中有住宅网络；波及已知来源；已验证机器人占命中 ≥ 20%；净新增 < 总量 1%；净新增远低于毛命中。例如：*毛命中 147,300，其中豁免 111,493（已验证机器人 111,493），净新增可拦 ≈ 35,800（占总量 0.2%）——建议降级为挑战或不处理。*

数字采用 FlareHound 的口径，与日报同样清洗（配置了 Workers 的 zone，空 UA 条目——Worker 内部记账——一律不计，并单列一行）；[校准](archive.md#calibration)后，计数旁同时显示面板口径的近似值。

## 能评估什么 {#what-can-be-evaluated}

Cloudflare **没有回放 API**。GraphQL 分析数据是采样聚合的数据集；逐请求日志只有 Logpush（企业版为主），FlareHound 不依赖它。模拟器把表达式翻译成维度过滤：

| 档 | 字段 | |
|---|---|---|
| 精确（采样） | `ip.src`（单个地址）、`ip.geoip.asnum` / `ip.src.asnum`、`ip.geoip.country` / `ip.src.country`、`http.user_agent`、`http.request.uri.path`、`http.request.uri.query`、`http.host`、`http.request.method`、`cf.client.bot`、`cf.verified_bot_category`，算子 `eq` `ne` `in` `contains` `starts_with()` `ends_with()`，以 `and` `or` `xor` `not` 与括号组合 | 否定下推到每个比较 |
| 上界 | `http.referer`——只有 referer 的 **host** 是维度（付费套餐）。`eq "https://site/"` 按来自 `site` 的全部 referer 计。处于否定之下时不允许（既不是精确值也不是上界）。`http.referer eq ""`（无 referer）是精确的 | 标签「上界」，点名子表达式 |
| 不可评估 | header、cookie、请求体、`matches`（正则）、`wildcard`、`cf.threat_score` / bot score、速率、`lower()` 等函数、`$list` 引用、网段（CIDR） | 点名并说明原因——**完全不给数**，绝不静默丢弃条件 |

每个字段都会对照该区套餐实际提供的维度检查（`flarehound doctor` 每区有一行 *rule simulator*）。**Free** 套餐没有 ASN 维度，也没有防火墙事件数据集：ASN 表达式在该区*不可评估*，净新增不可用——报告如实说明，不用其他口径凑数。

## 预算与缓存 {#budget-and-cache}

每次模拟最多 **24 次 GraphQL 查询**（通常 15–19 次），最多 4 个并发。**10 分钟**内的同一模拟走缓存（控制台；确认页与执行共用）。

## 封锁之后 {#after-the-block}

确认页上显示的模拟会**随封锁记录一起保存**（归档表 `block_sims`）。封前/封后对比（控制台与日报）随后增加一行：*预测净新增 ≈ 1,490 次/小时（确认时的模拟）；实际封禁后一小时拦截 1,320 次（−11%）*——预测偏差长期可见。「实际」取该规则的防火墙事件；没有防火墙事件的套餐会注明无法计量。

## 不做的事 {#not-done}

- 不做一键应用：报告不产生封锁方案，也没有写路径。
- 不做逐请求回放：不引入 Logpush，不落盘原始日志，采样就是精度上限。
- 不做跨 zone 模拟：表达式与规则集都是 zone 级的。
- 暂不支持：规则位置（前面的 skip 规则放行、前面的 block 先拿走）、挑战通过率、`$list` 展开。
