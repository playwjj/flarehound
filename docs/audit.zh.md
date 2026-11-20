# WAF 规则体检 {#waf-rule-audit}

FlareHound 读取你 zone 的自定义规则——只读，使用只读 Token——并像审阅者那样检查它们。它从不修改规则。

```bash
flarehound audit                     # all zones
flarehound audit --zone example.com
```

**权限：**只读 Token 上的 Zone → WAF: Read（规则集与 IP Access Rules 放行名单）；可选 Zone → Zone: Read，用于额度检查。没有 WAF: Read 时，体检报告「不可用」并说明原因，看守不受影响。见[权限](permissions.md)。

## 在哪里出现 {#where-it-appears}

| 位置 | 内容 |
|---|---|
| `flarehound audit` | 完整体检：规则清单、每一项覆盖结果、命中表 |
| 日报 | 没有问题时一行；否则只列需要关注的条目 |
| 小时级看守的每轮 | 每轮读取一次规则集版本（一次 REST 调用）。版本变化时重新体检，发现问题则单独发送一条 `kind: "audit"` 消息。第一次看到的版本只做记录。 |

用 `waf_audit.disabled: true` 关闭。

## 怎么修 {#how-to-fix}

完整体检（`flarehound audit`、控制台的 WAF 审计页、规则集变更消息）末尾有 **怎么修**：每项发现一条，说明该做什么并给出现成的命令——要么是填好输入的[规则配方](waf-guide.md#recipes)（`flarehound rules recipe protect-paths --path '/login*, /admin*'`），要么是 `rules move / delete / edit` 命令。你不运行就什么都不会改，而且每次变更都会先展示并确认。在控制台里，若控制台持有写 Token，管理员会看到 **用配方修复** 链接。

## 检查项 {#checks}

### 覆盖缺口 {#coverage-gaps}

敏感路径 = 设置了 zone 自己的 `cloudflare.zones[].waf_audit.sensitive_paths` 时用它，否则用默认清单 `path_rules` + `daily.paths` + `waf_audit.sensitive_paths`。有多个 zone 时，默认清单只属于全局 `waf_audit.hosts` 所在的 zone（未设置 hosts 时：第一个 zone）；其他没有自己清单的 zone，覆盖显示为 **未配置**——绝不会拿别的站点的路径来评判它。每个模式变成一个探测路径（`/login*` → `/login`，`/u/*/edit` → `/u/x/edit`），在该 zone 的每个主机上探测：zone 自己的 `waf_audit.hosts`，否则用属于它的全局 hosts，否则用 zone 名。按执行顺序逐条检查已启用的规则：

| 结果 | 含义 |
|---|---|
| **豁免（exempted）** | 一条跳过其后全部自定义规则的放行规则总是先匹配 |
| **覆盖（covered）** | 一条 block / challenge / js_challenge / managed_challenge 规则总是匹配（如果前面有条件性放行规则可能豁免部分请求，会注明） |
| **部分覆盖（partial）** | 只有按该路径选中的条件性防护（例如专为该路径写的爬虫 UA 拦截） |
| **缺口（gap）** | 没有任何防护规则专门作用于该路径 |

覆盖分**两级**报告：第一条防护规则的级别（*拦截*或*质询*），以及——当它是质询时——单独的拦截级，例如 `✓ /fake-follower*: challenge-level coverage by #13; block level: none (humans pass the challenge)`。被覆盖的路径不一定是被拦截的路径。

探测请求是该路径上的攻击者，所以它**不是 Cloudflare 已验证机器人**：像 `(path contains "/ranking") and not cf.client.bot` 这样的规则完全覆盖 `/ranking`。对所有路径一视同仁的规则——IP 名单、带 `robots.txt` 例外的爬虫 UA 拦截——不算任何特定路径的覆盖：一条规则只有在**不**匹配一个中性、无关的路径时，才算条件性覆盖。

### 顺序与冗余 {#ordering-and-redundancy}

只报告能证明的问题：

- 一条防护规则被它前面的放行规则完全覆盖——它永远不会生效；
- 前面的放行规则在某个敏感路径上与防护规则重叠——在那里可被绕过；
- 一条规则被更早的 **Block** 规则完全覆盖——它永远不会触发（质询规则不算遮蔽）；
- 重复——规范化后的条件相同、动作相同。

### 豁免 {#exemptions}

列出每条放行规则跳过了什么，以及其条件中用到的字段。条件只由任何客户端都能伪造的字段构成——User-Agent、Referer、host、路径 / URI / 查询串、方法、HTTP 版本、`X-Forwarded-For`——会被标为「任何人都能伪造」，并建议绑定 `ip.src`、`ip.geoip.asnum` 或密钥请求头（爬虫则用 `cf.client.bot`）。Cookie 和其他请求头不视为可伪造，因为它们可能携带密钥。IP Access Rules 中的放行条目也会列出，因为它们整体绕过 WAF。

### 命中与僵尸规则 {#hits-and-zombie-rules}

在有防火墙事件数据集的地方，按天统计每条规则最多 30 天的命中数，并显示 7 天与整个窗口的数字。窗口会被限制在该 zone 保留防火墙事件的时长内（有些套餐只保留 3 天；超出范围的查询会被拒绝），报告会说明覆盖了多少天。一条防护规则 **30 天内零命中**、且最近 30 天内未修改过，就报告为僵尸规则——只在完整覆盖 30 天时才这样判定；在只保留 3 天的 zone 上，安静三天什么也证明不了，所以不做僵尸判定——只报告，不删除：安静不等于没用。放行与 log 规则永远不算僵尸。在没有该数据集的套餐上（Free），这一节显示「不可用」，不做零命中结论。

### 额度 {#quota}

当规则数达到套餐自定义规则上限（Free 5 / Pro 20 / Business 100 / Enterprise 1,000）的 80% 时，体检会提示，并列出动作相同、可以用 `or` 合并的防护规则（FlareHound 自己的规则和带动作参数的规则除外）。

### 规则名称 {#rule-names}

读取规则集的同时，FlareHound 也拿到了每条规则的描述，因此报告里的防火墙事件显示名称而不是 ID。[`rule_names`](configuration.md#rule_names) 仍可覆盖它们。

## 如何对规则求值 {#how-it-evaluates-rules}

FlareHound 自带一个 Cloudflare 规则语言的解析器——支持 `and` / `or` / `xor` / `not` 及其符号形式，包括 `contains`、`matches`、`wildcard`、`strict wildcard` 与 `in` 在内的比较，集合与范围，`$lists`，函数调用，原始字符串，以及请求头映射访问。规则以**三值逻辑**对只固定了 `http.host` 和路径的探测请求求值：每条规则的结果是「总是匹配」「从不匹配」或「取决于其他字段」。无法解析的规则会列为解析失败，并从其他检查中排除，而不是去猜。
