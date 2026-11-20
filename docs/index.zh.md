# FlareHound {#flarehound}

**面向托管在 Cloudflare 上的网站的自托管流量控制台与看守工具。** FlareHound 用只读 Token 轮询 Cloudflare Analytics API，把每个整点小时与昨日同时段对比，将每个异常按路径、ASN、UA 和缓存状态拆解，只在确实需要你关注时发送一份简短的白话报告——先给结论，再附证据和处置建议。

Cloudflare 给数据，FlareHound 给结论。

## 主要功能 {#what-it-does}

| 功能 | 概要 | 页面 |
|---|---|---|
| 小时级看守 | zone 请求总量、未缓存（`dynamic`）响应、源站 5xx、源站不可达（52x）与源站延迟、Worker 调用量与 CPU P50、新面孔 UA / ASN、路径级阈值 | [检测](detection.md) |
| 静默告警 | 每个异常只告警一次；只有出现新信号或增长超过 25% 才再报；连续两轮无命中后发一条「恢复」消息 | [检测](detection.md#alert-discipline) |
| 归因与建议 | 贵贱分离，带置信度与证伪点的假设，封锁 / 质询 / 限速 / 缓存建议及可直接粘贴的表达式 | [报告](reports.md) |
| 日报 | 过去 24 小时对比前 24 小时、固定检查点、防火墙事件、封锁项尝试量、WAF 规则体检摘要、口径校准一行 | [报告](reports.md#daily-report) |
| 通知渠道 | Webhook、Telegram、JSONL 文件、Slack、Discord、企业微信、飞书 / Lark、邮件 | [通知渠道](channels.md) |
| 本地归档 | SQLite 单文件，保存约 13 个月的小时快照、近 4 周中位数基线、新面孔历史、告警历史 | [归档](archive.md) |
| 口径校准 | FlareHound 的数字与 Cloudflare 面板数字之间的关系 | [归档](archive.md#calibration) |
| 一键封锁 | IP / CIDR / ASN / 国家 / UA，带护栏、到期与审计日志（独立写 Token） | [封锁](blocking.md) |
| 规则变更 | 自定义规则、限速规则、缓存规则的新增、编辑、移动、删除与恢复，带备份与回读验证（独立写 Token） | [规则变更](rules.md) |
| WAF 规则体检 | 敏感路径覆盖缺口、被遮蔽的规则、可伪造的豁免、僵尸规则、额度 | [WAF 规则体检](audit.md) |
| Web 控制台 | 实时小时对比基线、涨降榜与下钻、新面孔、历史、WAF 规则体检与规则管理、设置、控制台内封锁、只读快照、多 zone 首页（管理员 / 查看者账号、TOTP、Google / GitHub 登录） | [控制台](console.md) |

## 设计原则 {#design-principles}

- **只读核心。** 看守进程只持有只读 Token。封锁与规则变更是单独的命令，使用各自的写 Token，并需要明确确认。
- **安静本身就是功能。** 没有异常，就没有消息。
- **先拆解，再下结论。** 每一次突增都先归因，再提出任何假设；结论确定且可复现——检测链路中没有 AI。
- **Token 不出门。** Token 只从环境变量读取，在日志中会被脱敏，且只发送到 `api.cloudflare.com`。

## 从哪里开始 {#where-to-start}

1. [快速开始](quickstart.md)——用 Docker 几分钟跑起来。
2. [API Token 与权限](permissions.md)——你需要的最小 Token。
3. [配置参考](configuration.md)——每个配置项及其默认值。

完整设计（中文）见 [SPEC.md](https://github.com/playwjj/flarehound/blob/main/SPEC.md)。本站也提供英文版——使用顶部的语言切换。
