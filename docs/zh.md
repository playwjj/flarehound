# 中文简介

**FlareHound 是一个自托管的开源工具，专为托管在 Cloudflare 上的网站做流量巡检。** 它用只读的 Cloudflare API Token 定期查询官方分析数据，按小时与昨日同时段对比，发现异常后先按路径 / ASN / UA / 缓存状态拆解归因，再把「结论 + 证据 + 处置建议」推送到你常用的通知渠道。没有异常就不说话。

Cloudflare 给数据，FlareHound 给结论。

## 主要功能

- **小时级看守**：zone 总量、未缓存（dynamic）响应、源站 5xx、Worker 调用量与 CPU P50、新面孔 UA / ASN、路径级阈值。详见 [检测](detection.md)。
- **静默纪律**：同一异常只报一次；出现新信号或已报信号再涨 25% 才再报；连续两轮无命中发一条恢复消息。
- **归因与建议**：贵贱分离（真实渲染与边缘缓存分开算）、带置信度与证伪点的机制假设、封禁 / 挑战 / 限速 / 缓存建议及可直接粘贴的规则表达式。详见 [告警、日报与建议](reports.md)。
- **每日报告**：过去 24 小时对比前 24 小时、固定检查点、防火墙事件、封锁项尝试量、WAF 体检摘要、口径校准一行。
- **通知渠道**：Webhook、Telegram、JSONL 文件、Slack、Discord、企业微信、飞书（可选签名）、邮件。详见 [通知渠道](channels.md)。
- **本地归档**：SQLite 单文件保存约 13 个月的小时快照，满 4 周后启用「近 4 周同时段中位数」长基线；可用 `-backfill 28` 立即补齐。详见 [本地归档与口径校准](archive.md)。
- **口径校准**：`flarehound calibrate` 对照 Cloudflare 面板数字。Free zone 实测 FlareHound 请求数约为面板的 1.29 倍、边缘 5xx 约 1.84 倍（缓存操作记账假象）。
- **一键封锁**：IP / 网段 / ASN / 国家 / UA，带护栏、到期自动解封与审计日志，使用独立写 Token。详见 [一键封锁](blocking.md)。
- **规则变更**：自定义、限速、缓存规则的增删改移与回滚，逐项确认、改前备份、回读验证。详见 [规则变更](rules.md)。
- **WAF 规则体检**：敏感路径覆盖缺口、被遮蔽的规则、可伪造的豁免、僵尸规则、额度，并给出「怎么修」。详见 [WAF 规则体检](audit.md)。
- **WAF 入门与规则配方**：放行 / 拦截 / 质询的基本原则，以及保护登录、限速、放行监控回调、放行已核验爬虫等现成配方，每条规则都附白话解释。详见 [WAF 入门](waf-guide-zh.md)。
- **Web 控制台**：实时小时、涨降榜与下钻、新面孔、历史、WAF 规则管理、控制台内拦截、只读快照，内置账号（含二次验证与 Google / GitHub 登录）。详见 [Web 控制台](console.md)。

## 快速开始

最小权限的只读 Token 只需 **Zone → Analytics: Read**；监控 Worker 时加 **Account → Account Analytics: Read**；WAF 体检加 **Zone → WAF: Read**。封锁与规则变更使用另一个写 Token（`CF_WRITE_TOKEN`）。完整说明见 [API Token 与权限](permissions.md)。

```bash
export CF_API_TOKEN=...
docker compose up -d
docker compose run --rm flarehound -config /app/config.json -once -dry-run
```

报告语言设为中文：`"report": {"language": "zh"}`。全部配置项见 [配置参考](configuration.md)，命令行见 [命令行](cli.md)，已知限制见 [限制](limitations.md)，常见问题见 [排错](troubleshooting.md)。

## 设计文档

完整的产品规格（中文）见 [SPEC.md](https://github.com/playwjj/flarehound/blob/main/SPEC.md)，其中各节的「实现口径」记录了实现决策与实测结论。
