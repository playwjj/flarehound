# WAF 入门（中文）

写给第一次配置 Cloudflare WAF 自定义规则的人：先讲五条原则，再讲怎么用 FlareHound 的**规则配方**照着做，最后列出常见错误。所有改动都要先看到完整的规则、确认后才执行，执行前自动备份、执行后读回核对，随时可以恢复。

## 五条原则

**1. 顺序决定一切。** 自定义规则从上往下执行，第一个匹配的「拦截」或「质询」就结束；「放行（Skip）」规则让请求跳过它指定的部分。推荐顺序：**放行 → 拦截 → 质询**。FlareHound 的配方会按这个顺序自动放到正确的位置。

**2. 放行搜索引擎靠 `cf.client.bot`，不靠 UA。** `cf.client.bot` 只有在 Cloudflare 核验过爬虫的 IP 与反向 DNS 后才为真（Googlebot、Bingbot 等）。UA 谁都能伪造——UA 里写着 Googlebot 什么也证明不了，按 UA 放行等于给所有人开后门（WAF 体检会把这类规则标为「任何人都能伪造」）。大多数时候你根本不需要单独的放行规则：在拦截 / 质询规则里加上 `and not cf.client.bot` 就够了，FlareHound 生成的规则都是这么写的。

**3. 拦截还是质询。**

| 用拦截（Block） | 用托管质询（Managed Challenge） |
|---|---|
| 云服务器 / 机房 ASN 上的爬虫 | 整个国家 |
| 单个攻击 IP | 家庭宽带、移动网络的 ASN |
| 指纹稳定的恶意 UA | 登录、后台、搜索等敏感路径 |
| 外人根本不该访问的路径（如 `/.env`） | 拿不准的情况 |

托管质询能拦住自动化客户端，真人只需点一下。拿不准时先质询，观察一段时间再决定要不要升级为拦截。

**4. 放行要窄。** 监控探针、支付回调、Webhook 这类必须放行的流量，条件要绑定**外人伪造不了的东西**：来源 IP / IP 段、网络（ASN）、或只有对方会发送的密钥请求头，并尽量限定路径。只跳过必须跳过的部分——默认只跳过「其后的自定义规则」，确有需要再加上限速、托管规则或超级机器人对抗模式。

**5. 敏感路径单独保护。** 登录、后台、搜索、API 用「质询 + 按 IP 限速」两层。WAF 体检会列出哪些敏感路径还没有任何防护（敏感路径来自配置里的 `path_rules`、`daily.paths` 与 `waf_audit.sensitive_paths`）。

## 用配方照着做

```bash
flarehound rules recipes          # 列出全部配方，带说明
flarehound audit                  # 体检，末尾「怎么修」给出可直接运行的命令
```

控制台里在 **WAF 规则 → 用配方添加规则**，或在 **WAF 审计** 的「怎么修」里点「用配方修复」。

| 配方 | 解决什么 | 例子 |
|---|---|---|
| `protect-paths` | 登录、后台等路径加质询（已核验爬虫除外） | `flarehound rules recipe protect-paths --path '/login*, /admin*'` |
| `ratelimit-paths` | 同一 IP 短时间内请求过多就质询 | `flarehound rules recipe ratelimit-paths --path '/login*' --requests 20` |
| `allow-service` | 放行监控 / Webhook（必须给出 IP、ASN 或密钥请求头） | `flarehound rules recipe allow-service --ips 203.0.113.10 --path '/webhooks/*'` |
| `allow-verified-bots` | 放行已核验的搜索引擎爬虫 | `flarehound rules recipe allow-verified-bots` |
| `challenge-cloud-on-paths` | 敏感路径上来自云服务器的流量要过质询 | `flarehound rules recipe challenge-cloud-on-paths --path '/login*'` |

密钥请求头的值不要写在命令行上（会留在 shell 历史里）：放进环境变量，再用 `--secret-env 变量名` 传入；控制台里则直接填在表单的密码框里。

执行前你会看到：配方说明、这条规则的白话解释（例如「如果路径以 /login 开头，且不是 Cloudflare 已核验的爬虫 → 托管质询」）、完整的规则字段、插入位置、额度变化与警告，然后才需要确认。

## 自己写规则时

```bash
flarehound rules list                       # 每条规则下有一行白话解释
flarehound rules add --action managed_challenge --expr '...' --desc '...'
flarehound rules add --action skip --skip rules,ratelimit --expr '...' --desc '...'
flarehound rules edit 3 --enabled false     # 先停用观察，比直接删除稳妥
flarehound rules move 3 --before 1
flarehound rules restore 12                 # 恢复改动前的备份
```

`--action skip` 必须说明跳过什么：`--skip rules`（其后的自定义规则，默认）、`ratelimit`、`managed`（托管规则，Pro 及以上）、`bots`（超级机器人对抗模式，Pro 及以上；Free 的 Bot Fight Mode 无法被规则跳过）、`legacy`（旧版安全功能），可逗号组合。不带跳过范围的放行规则 Cloudflare 会直接拒绝，FlareHound 会在发送前就提示。

## 常见错误

- **按 UA 放行 Googlebot**：任何人都能伪造。用 `cf.client.bot`。
- **放行规则放在最后**：前面的拦截已经生效了，放行永远轮不到。放行放最前面。
- **质询规则放在拦截规则前面**：两者都匹配的请求先碰到质询，拦截要等质询通过后才生效，命中统计也被质询「挡」在前面，难以判断拦截是否在起作用。明确的结论（拦截）放前面，质询放后面。
- **用国家或家宽 ASN 做拦截**：会误伤真人。用质询。
- **「放行我的办公室」只写了路径或 UA**：等于对所有人开门。绑定 IP 或密钥请求头。
- **Free 套餐的限速**：只有 1 条限速规则，周期与持续时间都必须是 10 秒。
- **规则额度用完**：Free 5 条、Pro 20 条。动作相同的规则可以用 `or` 合并，体检会列出可合并的规则。

## 改坏了怎么办

每次改动前都会备份整个阶段（归档 + `data/backups/` 下的 JSON 文件）。命令行用 `flarehound rules backups` 查看、`flarehound rules restore 编号` 恢复；控制台在 **WAF 规则** 页底部的「备份」里一键恢复。恢复本身也会先备份，所以恢复也能撤销。
