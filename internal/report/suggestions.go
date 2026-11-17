package report

import (
	"fmt"
	"strings"

	"github.com/playwjj/flarehound/internal/suggest"
)

// suggestions renders the suggestion block (SPEC 9): every item states
// what to do, the expression to paste, why, the expected gain, who it
// affects, and how to undo it. Header makes the read-only contract plain.
func (l lang) suggestions(b *strings.Builder, ss []suggest.Suggestion) {
	if len(ss) == 0 {
		return
	}
	b.WriteString("\n" + l.t("Suggestions (read-only — FlareHound never applies them; do it in the Cloudflare dashboard):\n",
		"处置建议（只读——FlareHound 不会执行，请在 Cloudflare 面板自行实施）：\n"))
	for i, s := range ss {
		title, where, why, gain, impact, rollback := l.suggestion(s)
		fmt.Fprintf(b, "%d. %s\n", i+1, title)
		if where != "" {
			fmt.Fprintf(b, "   %s %s\n", l.t("where:", "位置："), where)
		}
		if s.Expression != "" {
			fmt.Fprintf(b, "   %s %s\n", l.t("expression:", "表达式："), s.Expression)
		}
		fmt.Fprintf(b, "   %s %s\n", l.t("why:", "依据："), why)
		if gain != "" {
			fmt.Fprintf(b, "   %s %s\n", l.t("gain:", "收益："), gain)
		}
		fmt.Fprintf(b, "   %s %s\n", l.t("impact:", "影响面："), impact)
		if rollback != "" {
			fmt.Fprintf(b, "   %s %s\n", l.t("rollback:", "回滚："), rollback)
		}
	}
}

func (l lang) asnLabel(s suggest.Suggestion) string {
	net := map[suggest.Network]string{
		suggest.Hosting: l.t("hosting network", "机房/云网络"),
		suggest.Eyeball: l.t("residential/mobile network", "宽带/移动网络"),
		suggest.Unknown: l.t("network type unknown", "网络类型未知"),
	}[s.Network]
	if s.ASNName != "" {
		return fmt.Sprintf("%s (%s, %s)", s.Target, clip(s.ASNName, 40), net)
	}
	return fmt.Sprintf("%s (%s)", s.Target, net)
}

func (l lang) estGain(s suggest.Suggestion) string {
	if s.GainRequests <= 0 {
		return ""
	}
	return fmt.Sprintf(l.t("~%s fewer requests per window, of which ~%s expensive (estimate)", "每窗约减少 %s 次请求，其中昂贵部分约 %s（估算）"),
		n(s.GainRequests), n(s.GainExpensive))
}

func (l lang) suggestion(s suggest.Suggestion) (title, where, why, gain, impact, rollback string) {
	waf := l.t("Security → WAF → Custom rules", "安全性 → WAF → 自定义规则")
	undo := l.t("disable or delete the rule (takes effect in seconds)", "停用或删除该规则（秒级生效）")
	excess := fmt.Sprintf(l.t("%s requests vs %s yesterday, ~%s of the excess", "%s 次，昨日 %s 次，约占增量 %s"), n(s.Count), n(s.Base), share(s.Share))
	if s.Kind == suggest.ChallengePath || s.Kind == suggest.RateLimit {
		excess = fmt.Sprintf(l.t("%s uncached requests vs %s yesterday, ~%s of the dynamic excess", "%s 次未缓存请求，昨日 %s 次，约占 dynamic 增量 %s"), n(s.Count), n(s.Base), share(s.Share))
	}
	switch s.Kind {
	case suggest.BlockASN:
		return fmt.Sprintf(l.t("Block %s", "封禁 %s"), l.asnLabel(s)),
			waf + l.t(", action Block", "，动作 Block"),
			excess + l.t("; a hosting network, where no human visitors are expected.", "；机房网络，不应有真人访客。"),
			l.estGain(s),
			l.t("anything legitimately running on that network (your own monitors, partner APIs, uptime checkers) is blocked too; verified search bots stay allowed via `not cf.client.bot`.",
				"该网络上的一切正当客户端（自家监控、合作方 API、可用性探测）同样被拦；已验证的搜索引擎机器人经 `not cf.client.bot` 保留放行。"),
			undo
	case suggest.ChallengeASN:
		return fmt.Sprintf(l.t("Challenge %s — do NOT block", "挑战 %s——不要封禁"), l.asnLabel(s)),
			waf + l.t(", action Managed Challenge", "，动作 Managed Challenge"),
			excess + l.t("; real people browse from this kind of network, so a block would hit them (a backbone ASN block once did exactly that).",
				"；此类网络上有真实用户，封禁会误伤（骨干 ASN 封禁曾真实误伤用户）。"),
			"",
			l.t("every visitor from that network sees one passable challenge; automated clients without a browser stop.", "该网络的每位访客多一次可通过的挑战；无浏览器的自动化客户端会被挡下。"),
			undo
	case suggest.ChallengePath:
		why := excess
		if s.Share == 0 {
			why = fmt.Sprintf(l.t("sensitive path crossed its own line: %s requests vs %s yesterday", "敏感路径越过其专属阈值：%s 次，昨日 %s 次"), n(s.Count), n(s.Base))
		}
		return fmt.Sprintf(l.t("Challenge sensitive path %s", "对敏感路径 %s 启用挑战"), s.Target),
			waf + l.t(", action Managed Challenge (remove any skip/allow rule that exempts this path first)", "，动作 Managed Challenge（先取消对该路径的豁免规则）"),
			why,
			"",
			l.t("every visitor to this path sees one passable challenge; API clients or webhooks posting to it will break — exempt them by IP/ASN first.",
				"该路径的每位访客多一次可通过的挑战；向该路径发请求的 API 客户端或 Webhook 会失败——先按 IP/ASN 豁免它们。"),
			undo
	case suggest.RateLimit:
		return fmt.Sprintf(l.t("Rate-limit %s", "对 %s 限速"), s.Target),
			fmt.Sprintf(l.t("Security → WAF → Rate limiting rules; per IP, start at %d requests / %d s, action Managed Challenge, then tune with the next reports",
				"安全性 → WAF → 速率限制规则；按 IP 计，起步 %d 次 / %d 秒，动作 Managed Challenge，之后依日报调整"), s.RLRequests, s.RLPeriodSec),
			excess + l.t("; sources are dispersed, so blocking IPs will not work — capping each IP's rate does.", "；来源高度分散，封 IP 无效——限制单 IP 速率有效。"),
			"",
			l.t("heavy legitimate users of this path (power users, shared NAT/office IPs) may hit the limit and see a challenge.", "该路径的重度正当用户（高频用户、共享出口 IP 的办公网）可能触线并遇到挑战。"),
			undo
	case suggest.Cache:
		return fmt.Sprintf(l.t("Cache %s at the edge", "在边缘缓存 %s"), clip(s.Target, 60)),
			l.t("Caching → Cache Rules: eligible for cache, edge TTL 1 day (1 year if file names are content-hashed)", "缓存 → 缓存规则：符合缓存条件，边缘 TTL 1 天（文件名带内容哈希则 1 年）"),
			fmt.Sprintf(l.t("%s uncached responses for a static-looking file (%s yesterday)", "看似静态文件却有 %s 次未缓存响应（昨日 %s）"), n(s.Count), n(s.Base)),
			fmt.Sprintf(l.t("up to %s fewer Worker/origin hits per window", "每窗最多减少 %s 次 Worker/回源"), n(s.GainExpensive)),
			l.t("updates show up only after the TTL or a purge; if the response varies per user, do not cache it.", "更新需等 TTL 到期或手动清缓存后才可见；若响应因用户而异，切勿缓存。"),
			l.t("disable the cache rule and purge the URL", "停用缓存规则并清除该 URL 缓存")
	case suggest.CostHint:
		return fmt.Sprintf(l.t("Check Worker %s for a deploy change or a slow code path", "排查 Worker %s 的部署变更或慢路径"), s.Target),
			l.t("Workers → your Worker → Deployments / Metrics", "Workers → 该 Worker → 部署记录 / 指标"),
			fmt.Sprintf(l.t("CPU P50 %s with calls flat (%s vs %s)", "CPU P50 %s，而调用量平稳（%s vs %s）"), l.pct(s.CPUPct), n(s.Count), n(s.Base)),
			"",
			l.t("none — investigation only.", "无——仅需排查。"),
			""
	}
	return string(s.Kind), "", "", "", "", ""
}
