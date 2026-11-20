# API Token 与权限 {#api-tokens-permissions}

FlareHound 使用**两个独立的 Token**。看守进程只持有只读 Token；写 Token 只由封锁与规则变更命令读取（`block`、`unblock`、`blocks`、`enforce`、`rules`、`ratelimit`、`cache`）。

两个 Token 都在 *Cloudflare Dashboard → My Profile → API Tokens → Create Token → Custom token* 中创建。zone 权限的范围限定为你配置的 zone。

!!! note "权限名称"
    自定义规则始终需要 **Zone → WAF**（Read / Edit）。**IP Access Rules** 所需的权限因账户而异：有的账户由 Zone → WAF 覆盖；有的需要 **Firewall Services**，而较新的账户可能根本不提供该权限——还有些账户两者都无法授予。IP Access Rules 对 FlareHound 是可选的（用于体检中的放行名单检查，以及自定义规则额度用满时的回退）；没有它，相关功能会降级并明确说明。运行 [`flarehound doctor`](cli.md) 查看你的 Token 实际能访问什么。

## 只读 Token（`CF_API_TOKEN`） {#read-token-cf_api_token}

| 权限 | 用途 | 是否必需 |
|---|---|---|
| Zone → **Analytics: Read** | 看守测量的一切（GraphQL Analytics，包括能力探测） | **是——最低要求** |
| Account → **Account Analytics: Read** | Worker 调用量与 CPU P50（`workersInvocationsAdaptive` 是账户级数据集） | 仅当某个 zone 配置了 `workers` |
| Zone → **WAF: Read** | WAF 规则体检：读取自定义规则；报告中的规则名称；每轮的规则集版本检查（在部分账户上还包括 IP Access Rules）；控制台的 **WAF 规则** 页面（自定义规则与限速规则）；[规则模拟器](simulator.md)的规则位置（排在草稿前面的 skip 规则） | 用于 [WAF 规则体检](audit.md)、控制台规则页面与模拟器的规则位置 |
| Zone → **Zone: Read** | 读取套餐，用于体检中的额度检查 | 可选 |
| Account → **Account Filter Lists: Read** | [规则模拟器](simulator.md)展开 `$list` 引用（需配置 `cloudflare.account_id`） | 可选 |

只读 Token 的最低权限是从代码调用点推导出来的：看守的测量全部是 GraphQL Analytics 查询（`api.cloudflare.com/client/v4/graphql`）。唯一的例外是 WAF 规则体检：启用体检且 Token 具有 Zone → WAF: Read 时，每个小时轮次还会通过 REST 读取自定义规则集的版本（没有该权限时调用会静默失败，体检报告「不可用」）。旧版 README 还要求 Logs、Zone 和 Workers Scripts 的读取权限，但没有任何代码路径用到它们。要检查你自己的 Token，可以只授予 Zone → Analytics: Read 创建一个，然后运行 `flarehound -once -dry-run`。

没有 WAF: Read 时，体检显示为不可用并说明原因，看守不受影响、照常运行。

变量名可通过 `cloudflare.api_token_env` 配置（默认 `CF_API_TOKEN`）。该变量为空时 FlareHound 拒绝启动。

## 写 Token（`CF_WRITE_TOKEN`） {#write-token-cf_write_token}

切勿把它与只读 Token 合并；看守进程从不读取它。

| 权限 | 用途 |
|---|---|
| Account → **Account Filter Lists: Edit** | IP 封锁所用的 IP 列表 `flarehound_block` |
| Zone → **WAF: Edit** | 自定义规则（封锁、`rules`）、限速规则（`ratelimit`）；在部分账户上还包括 IP Access Rules 回退（其他账户上为 *Firewall Services: Edit*，如果提供的话） |
| Zone → **DNS: Read** | 读取你的 A / AAAA 记录，确保源站 IP 永远不会被封锁 |
| Zone → **Zone: Read** | 读取套餐以检查规则额度 |
| Zone → **Cache Rules: Edit** | 仅用于 `flarehound cache add` 和缓存阶段的变更 |

变量名可通过 `blocking.write_token_env` 配置（默认 `CF_WRITE_TOKEN`），且必须与 `cloudflare.api_token_env` 不同。

缺少某项写权限时会发生什么：

- **没有 Account Filter Lists**（或未配置 `cloudflare.account_id`）：IP 封锁改用表达式规则而不是列表——仍然只占一条自定义规则。
- **无法访问 IP Access Rules**：自定义规则额度用满时的回退不可用；封锁计划会说明这一点。
- **没有 DNS: Read**：IP 封锁会被拒绝，因为源站保护无法运行——除非你传入 `--skip-origin-check`。
- **没有 Cache Rules: Edit**：缓存阶段的命令会失败，并指出缺少的权限。

## Token 的处理方式 {#how-tokens-are-handled}

- Token 和渠道密钥只从环境变量读取，从不从配置文件读取。
- 所有日志输出都经过脱敏写入器：已加载的密钥值、`Bearer …` 字符串以及 Telegram 的 `/bot<token>` 片段都会被替换为 `[REDACTED]`。
- 通知渠道的错误信息从不包含端点 URL（webhook URL 中嵌有密钥）。
- 出站连接只发往 `api.cloudflare.com` 和你配置的通知端点。没有任何遥测。
