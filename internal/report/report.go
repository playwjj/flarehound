// Package report renders findings into the short, conclusion-first
// message format defined in SPEC.md section 11, in English or Chinese.
//
// Order is fixed: one-line conclusion; two-window numbers; attribution;
// hypotheses (each with confidence and a falsification point); block
// candidates. Sections without content are omitted, never padded.
package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/calibrate"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/state"
	"github.com/playwjj/flarehound/internal/suggest"
)

type lang string

func (l lang) t(en, zh string) string {
	if l == "zh" {
		return zh
	}
	return en
}

// n formats an integer with thousands separators.
func n(v int64) string {
	s := strconv.FormatInt(v, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func signed(v int64) string {
	if v >= 0 {
		return "+" + n(v)
	}
	return n(v)
}

func (l lang) pct(p float64) string {
	if p >= 999 {
		return l.t("new", "新增")
	}
	return fmt.Sprintf("%+.1f%%", p)
}

// change is a value with its change: "8,829 (+3.7%)", "37 (new)".
func (l lang) change(cur, base int64) string {
	return fmt.Sprintf(l.t("%s (%s)", "%s（%s）"), n(cur), l.delta(float64(cur), float64(base)))
}

func share(s float64) string { return fmt.Sprintf("%.0f%%", s*100) }

func clip(s string, max int) string {
	if s == "" {
		return "(empty)"
	}
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

func (l lang) window(w schedule.Window, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	f, t := w.From.In(loc), w.To.In(loc)
	tz := loc.String()
	if tz == "Local" {
		tz, _ = t.Zone()
	}
	if f.YearDay() == t.YearDay() || t.Sub(f) <= time.Hour {
		return fmt.Sprintf("%s %s–%s (%s)", f.Format("2006-01-02"), f.Format("15:04"), t.Format("15:04"), tz)
	}
	return fmt.Sprintf("%s → %s (%s)", f.Format("01-02 15:04"), t.Format("01-02 15:04"), tz)
}

// Finding renders one finding as a short line.
func (l lang) finding(f analyze.Finding) string {
	cur, base := int64(f.Cur), int64(f.Base)
	switch f.Rule {
	case analyze.RuleTotalUp:
		return l.t("Total requests ", "总请求 ") + l.change(cur, base)
	case analyze.RuleDynamicUp:
		return l.t("Requests the origin has to handle ", "需要源站处理的请求 ") + l.change(cur, base)
	case analyze.RuleOrigin5xx:
		return l.t("Origin errors (5xx) ", "源站报错（5xx）") + l.vs(cur, base, l.t("before", "之前"))
	case analyze.RuleUnreachable:
		return fmt.Sprintf(l.t("Cloudflare could not reach the origin %s times (52x; before %s)",
			"Cloudflare 连不上源站 %s 次（52x 错误；之前 %s）"), n(cur), n(base))
	case analyze.RuleOriginSlow:
		what := l.t("Origin time to first byte (P95) ", "源站首字节时间（P95）")
		if f.Subject == analyze.OriginTotal {
			what = l.t("Origin full response time (P95) ", "源站完整响应时间（P95）")
		}
		return what + l.vsMs(f.Cur, f.Base, l.t("before", "之前"))
	case analyze.RuleCollapseTotal:
		return l.t("Total requests dropped sharply ", "总请求骤降 ") + l.change(cur, base)
	case analyze.RuleWorkerCallsUp:
		return fmt.Sprintf(l.t("Worker %s calls ", "Worker %s 调用量 "), f.Subject) + l.change(cur, base)
	case analyze.RuleCollapseWorker:
		return fmt.Sprintf(l.t("Worker %s calls dropped sharply ", "Worker %s 调用骤降 "), f.Subject) + l.change(cur, base)
	case analyze.RuleCPUUp:
		return fmt.Sprintf(l.t("Worker %s median CPU per call %.1f ms (before %.1f ms, %s)", "Worker %s 单次 CPU 中位数 %.1f ms（之前 %.1f ms，%s）"),
			f.Subject, f.Cur, f.Base, l.delta(f.Cur, f.Base))
	case analyze.RulePathUp:
		return fmt.Sprintf(l.t("Path %s ", "路径 %s "), f.Subject) + l.change(cur, base)
	case analyze.RuleNewFaceUA:
		return fmt.Sprintf(l.t("New client in the top 10: %s, %s requests (not in yesterday's top 25)", "新的访问者进入前 10：%s，%s 次（昨天不在前 25）"),
			l.friendlyUA(f.Subject), n(cur)) + l.purposeTag(f.Purpose)
	case analyze.RuleNewFaceASN:
		return fmt.Sprintf(l.t("New network in the top 10: %s, %s requests (not in yesterday's top 25)", "新的来源网络进入前 10：%s，%s 次（昨天不在前 25）"),
			f.Subject, n(cur))
	}
	return f.String()
}

// findingLine is a finding for the "lines crossed" list: the finding,
// what a new ASN is (name and network type, so nobody looks it up by
// hand), and — once calibrated — what its count means in dashboard terms.
func (l lang) findingLine(f analyze.Finding, ratio float64, names, labels map[int]string, covered map[string]analyze.RuleCover) string {
	s := l.finding(f)
	if f.Rule == analyze.RuleNewFaceASN && f.ASN > 0 {
		name := names[f.ASN]
		shown := name
		if lb := labels[f.ASN]; lb != "" {
			shown = lb
		}
		kind := map[suggest.Network]string{
			suggest.Hosting: l.t("hosting/cloud network", "机房/云网络"),
			suggest.Eyeball: l.t("residential/mobile network", "宽带/移动网络"),
			suggest.Unknown: l.t("network type unknown", "网络类型未知"),
		}[suggest.Classify(f.ASN, name)]
		if shown != "" {
			kind = clip(shown, 40) + l.t(", ", "，") + kind
		}
		s += fmt.Sprintf(l.t(" [%s]", "【%s】"), kind)
	}
	if c, ok := covered[f.Key()+"|"+f.Subject]; ok {
		s += l.coverNote(c)
	}
	if ratio > 0 && dashTerms(f) {
		s += fmt.Sprintf(l.t(" (about %s as the Cloudflare dashboard counts)", "（按 Cloudflare 面板口径约 %s 次）"), n(int64(f.Cur/ratio)))
	}
	return s
}

// headline is the one-line conclusion: what needs attention, in plain
// titles, the most consequential first.
func (l lang) headline(fs []analyze.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	const show = 3
	var parts []string
	seen := map[string]bool{}
	for _, f := range sortedFindings(fs) {
		t := l.explain(f, analyze.Metrics{}, analyze.Metrics{}, "", nil, nil).Title
		if seen[t] {
			continue
		}
		seen[t] = true
		parts = append(parts, t)
	}
	head := strings.Join(parts[:min(show, len(parts))], l.t(", ", "、"))
	if len(parts) > show {
		if l == "zh" {
			head += fmt.Sprintf(" 等 %d 项", len(parts))
		} else {
			head += fmt.Sprintf(" and %d more", len(parts)-show)
		}
	}
	return head
}

// twoWindows is the numbers section: each value with what it was in the
// comparison window (was: "previous day", "same hour yesterday").
func (l lang) twoWindows(b *strings.Builder, cur, base analyze.Metrics, was string, unreachMin int64) {
	fmt.Fprintf(b, l.t("Traffic (compared with the %s):\n", "流量概况（对比%s）：\n"), was)
	fmt.Fprintf(b, "- %s%s\n", l.t("total requests: ", "总请求："), l.vs(cur.Total, base.Total, was))
	fmt.Fprintf(b, "- %s%s\n", l.t("requests the origin has to handle (not cached): ", "需要源站处理的请求（未命中缓存）："), l.vs(cur.Dynamic, base.Dynamic, was))
	fmt.Fprintf(b, "- %s%s%s\n", l.t("origin errors (5xx): ", "源站报错（5xx）："), l.vs(cur.Origin5xx, base.Origin5xx, was), l.errDetail(cur))
	if cur.Unreachable > 0 || base.Unreachable > 0 {
		fmt.Fprintf(b, "- %s%s%s\n", l.t("Cloudflare could not reach the origin (52x): ", "Cloudflare 连不上源站（52x）："),
			l.vs(cur.Unreachable, base.Unreachable, was), statusSplit(cur.UnreachableBy, l))
		if c := l.unreachableCheck(cur, base, unreachMin); c != "" {
			fmt.Fprintf(b, "  %s\n", c)
		}
	}
	if o := cur.Origin; o != nil {
		line := fmt.Sprintf(l.t("- origin response time of the slowest 5%% (P95): first byte %s, full response %s", "- 源站最慢 5%% 请求的响应时间（P95）：首字节 %s，完整响应 %s"), ms(o.TTFBP95ms), ms(o.TotalP95ms))
		if bo := base.Origin; bo != nil {
			line += fmt.Sprintf(l.t(" (%s %s / %s)", "（%s %s / %s）"), was, ms(bo.TTFBP95ms), ms(bo.TotalP95ms))
		}
		// Connections are mostly reused, so set-up P95s are often 0: only
		// worth a mention when they are not.
		if o.TCPP95ms > 0 || o.TLSP95ms > 0 {
			line += fmt.Sprintf(l.t("; connect TCP %s, TLS %s", "；建连 TCP %s、TLS %s"), ms(o.TCPP95ms), ms(o.TLSP95ms))
		}
		line += fmt.Sprintf(l.t("; over %s requests the origin answered\n", "；基于 %s 个源站回应的请求\n"), n(o.Requests))
		b.WriteString(line)
	}
	for _, w := range cur.Workers {
		bw := base.Worker(w.Name)
		line := fmt.Sprintf(l.t("- Worker %s: calls %s; CPU per call, median %.1f ms (%s %.1f ms, %s)", "- Worker %s：调用 %s；单次 CPU 中位数 %.1f ms（%s %.1f ms，%s）"), w.Name,
			l.vs(w.Calls, bw.Calls, was), w.CPUP50ms, was, bw.CPUP50ms, l.delta(w.CPUP50ms, bw.CPUP50ms))
		if w.CPUP99ms > 0 && bw.CPUP99ms > 0 {
			line += fmt.Sprintf(l.t(", slowest 1%% (P99) %.1f ms (%s %.1f ms, %s)", "，最慢 1%%（P99）%.1f ms（%s %.1f ms，%s）"), w.CPUP99ms, was, bw.CPUP99ms,
				l.delta(w.CPUP99ms, bw.CPUP99ms))
		}
		b.WriteString(line + "\n")
	}
}

// metricName names a tracked metric (baseline maturity) for the reader.
func (l lang) metricName(im analyze.Maturity) string {
	switch im.Metric {
	case analyze.MetricUnreachable:
		return l.t("52x errors (Cloudflare cannot reach the origin)", "52x 错误（Cloudflare 连不上源站）")
	case analyze.MetricOrigin:
		return l.t("origin latency", "源站延迟")
	case analyze.MetricCPUP99:
		return l.t("slowest-calls CPU (P99) of Worker ", "Worker 最慢调用 CPU（P99）") + im.Subject
	}
	return im.Metric
}

// unreachableCheck is the reading of the edge 52x (analyze.JudgeUnreachable,
// the same judgement as the alert line and the console tile): a
// bookkeeping background, or a departure from it and why. "" on a
// normally-zero baseline, where the bare numbers say it all.
func (l lang) unreachableCheck(cur, base analyze.Metrics, min int64) string {
	c := analyze.JudgeUnreachable(cur, base, min)
	switch c.Verdict {
	case analyze.UnreachBook:
		return fmt.Sprintf(l.t("verdict: Cloudflare's everyday background of 522/524, not an outage — they are %.1f%% of it, the usual level (%.1f×), and the origin keeps answering",
			"判断：这是 Cloudflare 日常就有的 522/524 记录，不是源站故障——522/524 占 %.1f%%，与平时同量级（%.1f 倍），源站照常回应"), c.BookShare*100, c.Jump)
	case analyze.UnreachIncident:
		var why []string
		if c.JumpHit {
			why = append(why, fmt.Sprintf(l.t("%.1f× the usual level", "是平时的 %.1f 倍"), c.Jump))
		}
		if c.MixHit {
			why = append(why, fmt.Sprintf(l.t("statuses other than 522/524: %s (%.0f%%)", "非 522/524 状态 %s 次（占 %.0f%%）"), n(c.Others), (1-c.BookShare)*100))
		}
		if c.CollapseHit {
			why = append(why, fmt.Sprintf(l.t("requests the origin answered %s", "源站回应的请求 %s"), l.pct(c.Collapse)))
		}
		return l.t("verdict: more than Cloudflare's everyday 522/524 background — ", "判断：超出 Cloudflare 日常的 522/524 记录——") + strings.Join(why, l.t("; ", "；"))
	}
	return ""
}

// unreachableAlert is the sub-line of an origin_unreachable alert: the
// status split (what the 52x are) and the judgement.
func (l lang) unreachableAlert(cur, base analyze.Metrics, min int64) string {
	s := ""
	if len(cur.UnreachableBy) > 0 {
		s = l.t("statuses: ", "构成：") + statusList(cur.UnreachableBy)
	}
	if c := l.unreachableCheck(cur, base, min); c != "" {
		if s != "" {
			s += l.t("; ", "；")
		}
		s += c
	}
	return s
}

// ms renders a latency: "803 ms", "1.4 s".
func ms(v float64) string {
	if v >= 1000 {
		return strconv.FormatFloat(v/1000, 'f', 1, 64) + " s"
	}
	return strconv.FormatFloat(v, 'f', 0, 64) + " ms"
}

// errDetail is the origin 5xx rate and status split, when known:
// "; 2.1% of origin answers; 502 ×80, 504 ×40".
func (l lang) errDetail(m analyze.Metrics) string {
	var parts []string
	if r, ok := m.Origin5xxRate(); ok && m.Origin5xx > 0 {
		parts = append(parts, fmt.Sprintf(l.t("%s of origin answers", "占回源响应 %s"), analyze.RatePct(r)))
	}
	if s := statusList(m.Origin5xxBy); s != "" {
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return ""
	}
	return l.t("; ", "；") + strings.Join(parts, l.t("; ", "；"))
}

// statusSplit is statusList in brackets: " (522 ×40, 521 ×3)".
func statusSplit(by map[string]int64, l lang) string {
	if len(by) == 0 {
		return ""
	}
	return l.t(" (", "（") + statusList(by) + l.t(")", "）")
}

// statusList renders a status breakdown, largest first: "522 ×40, 521 ×3".
// A single status is still shown: which one it is is the point.
func statusList(by map[string]int64) string {
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if by[keys[i]] != by[keys[j]] {
			return by[keys[i]] > by[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var ps []string
	for _, k := range keys {
		ps = append(ps, k+" ×"+n(by[k]))
	}
	return strings.Join(ps, ", ")
}

func (l lang) costLine(c analyze.Cost) string {
	oc, ob := c.ExpCur-c.DynCur, c.ExpBase-c.DynBase
	return fmt.Sprintf(l.t("served from the edge cache %s; other cache misses (miss / bypass / expired) %s",
		"由缓存直接返回 %s；其他未命中缓存（miss / bypass / expired）%s"),
		l.change(c.CheapCur, c.CheapBase), l.change(oc, ob))
}

func faceList(fs []cfapi.Face, max int) string {
	var parts []string
	for i, f := range fs {
		if i >= max {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", clip(f.Name, 60), n(f.Count)))
	}
	return strings.Join(parts, ", ")
}

// ip is an address (or CIDR) followed by its IP location —
// "106.201.104.211 [IN · India]", "106.201.104.211 [印度 (IN)]" — or
// the text unchanged when it is not an address or the library is off.
func (l lang) ip(s string) string { return s + geoip.Suffix(s, string(l)) }

// ipList is faceList for client IPs, each with its IP location.
func (l lang) ipList(fs []cfapi.Face, max int) string {
	var parts []string
	for i, f := range fs {
		if i >= max {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", l.ip(clip(f.Name, 60)), n(f.Count)))
	}
	return strings.Join(parts, ", ")
}

func (l lang) hypothesis(h analyze.Hypothesis) (claim, falsifier string) {
	switch h.ID {
	case analyze.HypNewFaceSurge:
		return fmt.Sprintf(l.t("Crawler/bot surge: new source %s carries ~%s of the excess.", "爬虫 / 机器人在加量：新来源 %s 约占增量的 %s。"), clip(h.Subject, 60), share(h.Share)),
			l.t("its path mix matches normal visitors and it comes from residential/mobile networks — then it is more likely real traffic (campaign, hot content).",
				"该来源的路径分布与常态访客一致、且来自宽带/移动网络——那更可能是真实流量（推广、热点）。")
	case analyze.HypCheapVolume:
		return fmt.Sprintf(l.t("~%s of the excess is cheap edge-cached volume; the real cost impact is small.", "约 %s 的增量是边缘缓存命中的便宜量，实际成本影响小。"), share(h.Share)),
			l.t("Worker CPU, requests that reach the origin or origin errors rose as well.", "Worker CPU、需要源站处理的请求或源站报错同时上涨。")
	case analyze.HypCacheRegress:
		return l.t("Uncached responses rose while total volume did not: a cache rule, cache-busting query strings or a deploy may have reduced cacheability.",
				"总量未涨而未缓存响应上涨：缓存规则变更、带随机参数的请求或一次部署可能降低了可缓存性。"),
			l.t("the increase in requests that reach the origin comes from one new source — then it is a crawler hitting uncached pages.",
				"回源请求的增量集中在某一个新来源——那是爬虫在抓没有缓存的页面。")
	case analyze.HypSlowPath:
		return fmt.Sprintf(l.t("Worker %s burns more CPU per call without more calls: likely a deploy change or a slow code path.", "Worker %s 调用量平稳但单次 CPU 上涨：疑为部署变更或慢路径。"), h.Subject),
			l.t("the request mix shifted to heavier paths (see the paths that reach the origin most).", "请求构成转向了更重的路径（见回源最多的路径）。")
	case analyze.HypCPUMix:
		return fmt.Sprintf(l.t("Worker %s: the request mix changed, the cost did not — CPU P50 rose while P99 stayed about flat and calls fell. Cheap calls left (e.g. a flood receding) and the median moved up. Reported at low severity.",
				"Worker %s：请求构成变了，并非变贵——CPU 中位数上涨，但最慢 1%%（P99）基本持平、调用量下降。便宜的调用少了（比如一波流量退去），中位数就被抬高。按轻微处理。"), h.Subject),
			l.t("P99 rises in the next rounds too, or calls recover while P50 stays high — then calls really got more expensive.",
				"后续几轮 P99 也上涨，或调用量回升而中位数仍高——那就是真变贵了。")
	case analyze.HypCPUCostly:
		return fmt.Sprintf(l.t("Worker %s calls really got more expensive: CPU P50 and P99 rose together while calls held — a code change, a slower dependency or heavier requests.",
				"Worker %s 单次调用确实变贵了：CPU 中位数与最慢 1%%（P99）一起上涨，调用量没跌——可能是代码变更、依赖变慢或请求变重。"), h.Subject),
			l.t("the rise lines up with a shift to heavier paths (see the paths that reach the origin most) and no deploy — then it is the load, not the code.",
				"上涨与请求转向更重的路径同时发生（见回源最多的路径）且无部署——那是负载而非代码。")
	case analyze.HypOriginFailure:
		return l.t("The origin is failing or overloaded.", "源站故障或过载。"),
			l.t("the 5xx concentrate on a single route — then it is an application bug on that route.", "5xx 集中在单一路径——那是该路由的应用缺陷。")
	case analyze.HypRouteBug:
		return fmt.Sprintf(l.t("Application bug on one route: %s of the origin 5xx come from %s.", "单一路由的应用缺陷：%s 的源站 5xx 来自 %s。"), share(h.Share), clip(h.Subject, 60)),
			l.t("the same route also fails for other methods or the 5xx spread to other paths — then it is an origin-wide problem.",
				"5xx 扩散到其他路径——那就是源站整体问题。")
	case analyze.HypOriginDown:
		return l.t("The origin is down or unreachable from Cloudflare: 52x means the edge never got an answer (521 refused, 522/524 timed out, 523 no route, 525/526 TLS).",
				"源站宕机或 Cloudflare 连不上：52x 表示边缘根本没拿到源站回应（521 拒绝连接，522/524 超时，523 无路由，525/526 TLS 握手/证书）。"),
			l.t("the origin answers direct requests normally and only some Cloudflare data centres see 52x — then it is a network path or firewall (origin blocking Cloudflare IPs) problem.",
				"直连源站正常、且只有部分 Cloudflare 机房出现 52x——那是网络路径或防火墙（源站拦了 Cloudflare IP）问题。")
	case analyze.HypOriginLoad:
		return l.t("The origin is slowing under more work: more uncached requests reach it at the same time (see the paths that reach the origin and new clients).",
				"源站在更多负载下变慢：同时段有更多未缓存请求打到源站（见回源最多的路径和新的访问者）。"),
			l.t("the origin stays slow after the extra traffic is blocked or cached — then the machine itself degraded.",
				"拦截或缓存掉增量后源站仍然慢——那是机器本身出了问题。")
	case analyze.HypOriginSlow:
		if h.Subject == analyze.OriginTotal {
			return l.t("Origin responses take longer to transfer while first byte is steady: large bodies or limited bandwidth (hotlinking, downloads).",
					"首字节平稳而完整响应变慢：响应体变大或带宽受限（盗链、大文件下载）。"),
				l.t("the slow responses are small pages — then the origin's network is congested.", "慢的都是小页面——那是源站网络拥塞。")
		}
		return l.t("The origin computes slower with load flat: application or database (slow query, lock, cron job, plugin update, exhausted PHP workers).",
				"负载平稳而源站计算变慢：应用或数据库问题（慢查询、锁、定时任务、插件更新、PHP 进程池耗尽）。"),
			l.t("the origin's work shifted to a heavier path (see origin requests by path) — then it is that route, not the machine.", "回源请求转向了更重的路径（见源站处理的请求按路径）——那是该路由的问题，而非整机。")
	case analyze.HypCollapse:
		return l.t("Traffic drop: upstream outage, DNS/routing change, or a blocking rule hitting real visitors.",
				"流量塌陷：上游故障、DNS/路由变更，或拦截规则误伤真实访客。"),
			l.t("firewall events rose at the same time — then a rule is blocking (check whether that is intended).",
				"同时段防火墙事件上涨——那是规则在拦截（核对是否预期）。")
	case analyze.HypDiffuse:
		return l.t("Growth without a concentrated driver: could be legitimate (campaign, hot content) or a widely distributed source. Evidence is insufficient for a mechanism claim.",
				"增长无集中驱动：可能是正当流量（推广、热点），也可能是高度分散的来源。证据不足，不下机制结论。"),
			l.t("a single source or path dominates the excess in the next round.", "下一轮出现单一来源或路径主导增量。")
	}
	return h.ID, ""
}

func (l lang) confidence(c string) string {
	switch c {
	case analyze.High:
		return l.t("likely", "可能性高")
	case analyze.Medium:
		return l.t("possible", "可能性中")
	}
	return l.t("unsure", "可能性低")
}

// IntradayData is everything one intraday round produced.
type IntradayData struct {
	Zone        string
	Window      schedule.Window
	Loc         *time.Location
	Decision    state.Decision
	Cur, Base   analyze.Metrics
	Findings    []analyze.Finding
	Attr        analyze.Attribution
	Hypotheses  []analyze.Hypothesis
	Block       analyze.BlockAdvice
	Suggestions []suggest.Suggestion
	Since       time.Time        // episode start
	Long        *analyze.Metrics // 4-week same-hour median, when the archive has enough samples
	LongN       int              // samples behind Long (or collected so far)
	Severity    analyze.Severity
	DashRatio   float64 // FlareHound/dashboard request ratio from calibration; 0 = unknown
	// UnreachableMin is thresholds.unreachable_min (the 52x judgement's floor).
	UnreachableMin int64
}

// Intraday renders an intraday alert / escalation / recovery message:
// line 1 names the zone and the kind of message, line 2 says what needs
// attention in plain words; then each finding explained with a next step,
// the numbers, and the details.
func Intraday(language string, d IntradayData) string {
	l := lang(language)
	if d.Decision == state.DecRecovered {
		return fmt.Sprintf(l.t("FlareHound · %s back to normal ✅ — several rounds in a row at the normal level again (last window %s).",
			"FlareHound · %s 已恢复正常 ✅——连续几轮都回到了平时水平（最近窗口 %s）。"),
			d.Zone, l.window(d.Window, d.Loc))
	}
	var b strings.Builder
	head := map[state.Decision]string{
		state.DecAlert:    l.t("something is off", "发现异常"),
		state.DecChanged:  l.t("the anomaly changed (a new signal)", "异常有新变化"),
		state.DecEscalate: l.t("the anomaly got worse", "异常加重"),
	}[d.Decision]
	mark := "⚠️ "
	if d.Severity.Level == analyze.SevLow && d.Decision == state.DecAlert {
		mark = "🟡 "
		head = l.t("minor: a traffic surge the cache absorbed", "轻微：流量突增，但被缓存挡住了")
		if d.Severity.Kind == analyze.CPUMixKind {
			head = l.t("minor: Worker CPU moved because the request mix changed", "轻微：请求构成变化导致 Worker CPU 波动")
		}
	}
	fmt.Fprintf(&b, "FlareHound · %s — %s\n", d.Zone, head)
	fmt.Fprintf(&b, "%s%s%s\n", mark, l.t("Needs a look: ", "需要关注："), l.headline(d.Findings))
	fmt.Fprintf(&b, "%s %s", l.t("Window", "时间"), l.window(d.Window, d.Loc))
	if d.Decision != state.DecAlert && !d.Since.IsZero() {
		fmt.Fprintf(&b, l.t("; started %s", "；本次异常始于 %s"), d.Since.In(locOr(d.Loc)).Format("01-02 15:04"))
	}
	b.WriteString("\n\n")
	if d.Severity.Kind == analyze.EdgeAbsorbed {
		fmt.Fprintf(&b, l.t("The extra traffic is absorbed by the cache: requests the origin handles %s, CPU and origin errors normal — no pressure on the origin or the Worker. Watch it, nothing to do.\n\n",
			"增量被缓存挡住了：需要源站处理的请求 %s，CPU 和源站报错都正常——源站和 Worker 没有压力。观察即可，无需处理。\n\n"), l.pct(d.Severity.DynPct))
	}
	was := l.t("same hour yesterday", "昨日同时段")
	l.lead(&b, d.Findings, d.Cur, d.Base, was, d.DashRatio, d.Attr.ASNNames, d.Attr.ASNLabels, d.Attr.Covered, d.UnreachableMin)
	l.twoWindows(&b, d.Cur, d.Base, was, d.UnreachableMin)
	if d.Long != nil {
		fmt.Fprintf(&b, l.t("- normal level over the last 4 weeks, same hour (%d samples): requests %s, origin requests %s, origin errors %s — every volume signal above is above this too\n",
			"- 过去 4 周同时段的平时水平（%d 个样本）：总请求 %s，需源站处理 %s，源站报错 %s——上面的流量类异常也都超出了这个水平\n"),
			d.LongN, n(d.Long.Total), n(d.Long.Dynamic), n(d.Long.Origin5xx))
	}

	a := d.Attr
	var attr []string
	if len(a.CacheCur) > 0 {
		attr = append(attr, l.costLine(analyze.SplitCost(a.CacheCur, a.CacheBase)))
	}
	if len(a.DynamicPaths) > 0 {
		var ps []string
		for _, p := range a.DynamicPaths {
			ps = append(ps, fmt.Sprintf(l.t("%s %s (yesterday %s)", "%s %s（昨日 %s）"), clip(p.Path, 60), n(p.Cur), n(p.Base)))
		}
		attr = append(attr, l.t("paths that reach the origin most: ", "回源最多的路径：")+strings.Join(ps, ", "))
	}
	keys := make([]string, 0, len(a.FacePaths))
	for k := range a.FacePaths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attr = append(attr, fmt.Sprintf(l.t("%s mostly fetches: %s", "%s 主要访问：%s"), clip(k, 60), faceList(a.FacePaths[k], 3)))
	}
	if a.FaceHistory != nil {
		young := a.ArchiveDays < analyze.FaceHistoryMinDays
		hasNew := false
		for _, f := range d.Findings {
			if f.Rule != analyze.RuleNewFaceUA && f.Rule != analyze.RuleNewFaceASN {
				continue
			}
			hasNew = true
			if h, ok := a.FaceHistory[f.Subject]; ok {
				attr = append(attr, fmt.Sprintf(l.t("%s seen before: first %s, last %s, at most %s per hour", "%s 以前来过：首次 %s，最近 %s，最多每小时 %s 次"),
					clip(f.Subject, 60), h.First.In(locOr(d.Loc)).Format("2006-01-02 15:04"), h.Last.In(locOr(d.Loc)).Format("01-02 15:04"), n(h.MaxCount)))
			} else if !young {
				attr = append(attr, fmt.Sprintf(l.t("%s: never seen before", "%s：以前从没来过"), clip(f.Subject, 60)))
			}
		}
		if young && hasNew {
			attr = append(attr, fmt.Sprintf(l.t("whether it came before is not judged yet: only %d day(s) of local history (needs %d; `flarehound -backfill 28` fills it now)",
				"还不能判断以前是否来过：本地历史只有 %d 天（需 %d 天；运行 `flarehound -backfill 28` 可立即补齐）"), a.ArchiveDays, analyze.FaceHistoryMinDays))
		}
	}
	for _, im := range a.Impostors {
		attr = append(attr, l.impostor(im))
	}
	if len(a.Origin5xxPaths) > 0 {
		attr = append(attr, l.t("origin errors (5xx) by path: ", "源站报错（5xx）按路径：")+faceList(a.Origin5xxPaths, 5))
	}
	if len(a.OriginPaths) > 0 {
		attr = append(attr, l.t("origin requests by path: ", "源站处理的请求按路径：")+faceList(a.OriginPaths, 5))
	}
	if len(a.TopIPs) > 0 {
		attr = append(attr, l.t("top client IPs: ", "请求最多的 IP：")+l.ipList(a.TopIPs, 5))
	}
	if len(a.Firewall) > 0 {
		attr = append(attr, l.t("firewall events (blocked / challenged): ", "防火墙事件（拦截 / 挑战）：")+faceList(a.Firewall, 5))
	}
	if len(a.VerifiedBots) > 0 {
		attr = append(attr, l.t("verified crawlers (not counted as new clients): ", "已验证的正规爬虫（不算新访问者）：")+strings.Join(a.VerifiedBots, ", "))
	}
	if len(a.Unsettled) > 0 {
		attr = append(attr, l.t("not judged yet, data still arriving: ", "数据还没到齐，暂不判断：")+strings.Join(a.Unsettled, ", "))
	}
	if len(attr) > 0 {
		b.WriteString("\n" + l.t("Where it comes from:\n", "来源细节：\n"))
		for _, s := range attr {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}

	if len(d.Hypotheses) > 0 {
		b.WriteString("\n" + l.t("Likely causes:\n", "可能的原因：\n"))
		for _, h := range d.Hypotheses {
			claim, fals := l.hypothesis(h)
			fmt.Fprintf(&b, "- [%s] %s\n", l.confidence(h.Confidence), claim)
			if fals != "" {
				fmt.Fprintf(&b, "  %s%s\n", l.t("Not this if: ", "如果出现以下情况，就不是这个原因："), fals)
			}
		}
	} else {
		b.WriteString("\n" + l.t("Not enough evidence to name a cause yet — numbers only.\n", "目前证据还不足以判断原因，先报数字。\n"))
	}

	if len(d.Block.Candidates) > 0 {
		b.WriteString("\n" + l.t("IPs you could block:\n", "可以考虑封禁的 IP：\n"))
		for _, c := range d.Block.Candidates {
			fmt.Fprintf(&b, l.t("- IP %s: %s requests, ~%s of the excess\n", "- IP %s：%s 次，约占增量 %s\n"), l.ip(c.IP), n(c.Count), share(c.Share))
			if t, err := block.Parse("ip", c.IP); err == nil {
				fmt.Fprintf(&b, "  %s %s\n", l.t("one-click:", "一键执行："), block.Command(t, block.Block, "24h", ""))
			}
		}
	} else if d.Block.Dispersed {
		b.WriteString("\n" + l.t("The traffic is spread over many IPs (none carries 1% of the increase): blocking IPs one by one will not help — act on the network or the path (a challenge).\n",
			"流量分散在大量 IP 上（单个 IP 都不到增量的 1%）：逐个封 IP 没用，应按来源网络或路径处理（挑战）。\n"))
	}
	if len(d.Block.Excluded) > 0 {
		b.WriteString("\n" + l.t("Large sources you should NOT block:\n", "量大但不能封的来源：\n"))
		for _, c := range d.Block.Excluded {
			if c.Cloudflare {
				fmt.Fprintf(&b, l.t("- IP %s: %s requests, ~%s of the excess — Cloudflare's own address (%s). This is Worker egress: a Worker (yours, or another zone's) fetching this site. Find the calling Worker; blocking would cut off your own services.\n",
					"- IP %s：%s 次，约占增量 %s——Cloudflare 自有地址（%s）。这是 Worker 出口：某个 Worker（你自己的或其他站点的）在调用本站。应去找调用方 Worker；封它会切断自家服务。\n"),
					l.ip(c.IP), n(c.Count), share(c.Share), c.Protected)
			} else {
				fmt.Fprintf(&b, l.t("- IP %s: %s requests, ~%s of the excess — protected: %s\n", "- IP %s：%s 次，约占增量 %s——受保护：%s\n"),
					l.ip(c.IP), n(c.Count), share(c.Share), c.Protected)
			}
		}
	}
	l.suggestions(&b, d.Suggestions)
	return strings.TrimRight(b.String(), "\n")
}

func locOr(l *time.Location) *time.Location {
	if l == nil {
		return time.UTC
	}
	return l
}

// Checkpoint is one daily fixed path checkpoint result.
type Checkpoint struct {
	Label       string
	Path        string
	OriginReach int64
	Max         int64
}

// ArtifactCount is one known accounting artifact's count.
type ArtifactCount struct {
	Label string
	Count int64
}

// BlockEffectLine is a block made in the report window, with what it did.
type BlockEffectLine struct {
	Target, Action string
	At             time.Time
	Verdict        string
}

// SimAccuracy is the rule simulator's record: for blocks confirmed after a
// simulation, the net new it predicted per hour against what the rule
// stopped in the hour after.
type SimAccuracy struct {
	Days      int     // the look-back (30)
	Predicted int     // blocks with a prediction
	Measured  int     // … whose hour after was counted
	Upper     int     // … of which the prediction was an upper bound
	MedianDev float64 // median (actual − predicted) / predicted
	Worst     string  // target with the widest deviation
	WorstDev  float64
}

// BlockStatus is one active FlareHound block for the daily checkpoint.
type BlockStatus struct {
	Target     string
	Action     string
	Attempts   int64
	AttemptsNA bool
	// Approx: Attempts is summed from the archived IP board (no firewall
	// events on the plan); LastHour is the last hour the IP made the list.
	Approx    bool
	LastHour  time.Time
	Since     time.Time
	ExpiresAt time.Time
}

// ArchiveInfo summarises the local archive for the daily report.
type ArchiveInfo struct {
	Hours, Days int64
	Oldest      time.Time
	LongSamples int
	// Warming: lines whose archive baseline started accumulating in this
	// window; they stay quiet until enough days measured the same hour.
	Warming []analyze.Maturity
}

// DailyData is everything the daily report shows.
type DailyData struct {
	Zone              string
	Window            schedule.Window
	Loc               *time.Location
	Cur, Base         analyze.Metrics
	Findings          []analyze.Finding
	VerifiedBots      []string
	Impostors         []analyze.Impostor
	Cost              *analyze.Cost
	DynamicPaths      []analyze.PathDelta
	Firewall          []cfapi.Face
	FirewallNA        bool
	NoASN             bool // plan exposes no ASN dimension
	MitigatedIPs      []cfapi.Face
	Checkpoints       []Checkpoint
	Artifacts         []ArtifactCount
	Suggestions       []suggest.Suggestion
	Archive           *ArchiveInfo
	Audit             *AuditData
	Calibration       *calibrate.Summary
	ASNNames          map[int]string
	ASNLabels         map[int]string // operator's short names
	Covered           map[string]analyze.RuleCover
	Blocks            []BlockStatus
	BlockEffects      []BlockEffectLine // blocks made in the window, before / after
	SimAccuracy       *SimAccuracy      // rule simulator: predicted vs actual over 30 days
	ActiveSince       time.Time
	ActiveFingerprint string
	Gaps              []string
	UnreachableMin    int64 // thresholds.unreachable_min (the 52x judgement's floor)
	// RecordedFaces are new training crawlers: recorded, not alerted on.
	RecordedFaces []analyze.Finding
	Purpose       *PurposeData // traffic by purpose; nil: table off or not measured
	// HideStatus leaves out the system-status block (plan limits, archive,
	// counting basis): it is said when it changes and weekly (StatusKey).
	HideStatus bool
}

// Daily renders the daily report.
func Daily(language string, d DailyData) string {
	l := lang(language)
	var b strings.Builder
	fmt.Fprintf(&b, l.t("FlareHound daily · %s\n", "FlareHound 日报 · %s\n"), d.Zone)

	// Line 2: the conclusion. Line 3: the window.
	var warn []string
	for _, c := range d.Checkpoints {
		if c.OriginReach > c.Max {
			warn = append(warn, c.Label)
		}
	}
	switch {
	case len(d.Findings) == 0 && len(warn) == 0:
		b.WriteString(l.t("✅ All normal: nothing above its normal range, every check within limits.\n", "✅ 一切正常：没有指标超出平时范围，例行检查全部通过。\n"))
	case len(d.Findings) > 0:
		fmt.Fprintf(&b, l.t("⚠️ Needs a look: %s\n", "⚠️ 需要关注：%s\n"), l.headline(d.Findings))
	default:
		fmt.Fprintf(&b, l.t("⚠️ Check over its limit: %s\n", "⚠️ 例行检查超限：%s\n"), strings.Join(warn, ", "))
	}
	fmt.Fprintf(&b, "%s %s\n", l.t("Window", "时间"), l.window(d.Window, d.Loc))
	b.WriteString(l.purposeShifts(d.Purpose))
	b.WriteString("\n")

	if !d.ActiveSince.IsZero() {
		fmt.Fprintf(&b, l.t("An anomaly found during the day is still open (since %s).\n\n", "白天发现的异常还没恢复（始于 %s）。\n\n"),
			d.ActiveSince.In(locOr(d.Loc)).Format("01-02 15:04"))
	}
	was := l.t("previous day", "前一天")
	ratio := 0.0
	if d.Calibration != nil {
		ratio = d.Calibration.Requests
	}
	l.lead(&b, d.Findings, d.Cur, d.Base, was, ratio, d.ASNNames, d.ASNLabels, d.Covered, d.UnreachableMin)

	if len(d.BlockEffects) > 0 {
		b.WriteString(l.t("Blocks made in the window and what they did (the hour before vs the hour after):\n",
			"这段时间新加的封禁及效果（封禁前一小时 vs 封禁后一小时）：\n"))
		for _, x := range d.BlockEffects {
			fmt.Fprintf(&b, l.t("- %s (%s, %s): %s\n", "- %s（%s，%s）：%s\n"), x.Target, x.Action, x.At.In(locOr(d.Loc)).Format("01-02 15:04"), x.Verdict)
		}
		b.WriteString("\n")
	}
	if a := d.SimAccuracy; a != nil && a.Predicted > 0 {
		b.WriteString(l.simAccuracy(*a) + "\n")
	}

	l.twoWindows(&b, d.Cur, d.Base, was, d.UnreachableMin)
	if d.Cost != nil {
		fmt.Fprintf(&b, "- %s\n", l.costLine(*d.Cost))
	}

	if len(d.DynamicPaths) > 0 {
		b.WriteString("\n" + l.t("Paths that reach the origin most:\n", "回源最多的路径（需要源站处理）：\n"))
		for _, p := range d.DynamicPaths {
			fmt.Fprintf(&b, "- %s %s\n", clip(p.Path, 70), l.change(p.Cur, p.Base))
		}
	}
	l.faces(&b, l.t("Main source networks", "主要来源网络"), d.Cur.TopASN, d.Base.TopASN, false)
	l.faces(&b, l.t("Main clients", "主要访问者"), d.Cur.TopUA, d.Base.TopUA, true)
	if len(d.VerifiedBots) > 0 {
		fmt.Fprintf(&b, "- %s%s\n", l.t("verified crawlers: ", "已验证的正规爬虫："), strings.Join(d.VerifiedBots, ", "))
	}
	for _, im := range d.Impostors {
		fmt.Fprintf(&b, "- %s\n", l.impostor(im))
	}
	for _, f := range d.RecordedFaces {
		fmt.Fprintf(&b, "- %s\n", l.recordedFace(f))
	}
	l.purposeSection(&b, d.Purpose, !d.NoASN)

	var checks []string
	switch {
	case d.FirewallNA:
		// said in the system status
	case len(d.Firewall) == 0:
		checks = append(checks, l.t("- firewall (blocked / challenged): nothing\n", "- 防火墙拦截 / 挑战：无\n"))
	default:
		s := l.t("- firewall events by rule (attempts — what decides when to lift a block):\n", "- 各规则拦下的请求（尝试次数——决定何时解封的依据）：\n")
		for _, f := range d.Firewall {
			s += fmt.Sprintf("  %s: %s\n", f.Name, n(f.Count))
		}
		checks = append(checks, s)
	}
	if len(d.MitigatedIPs) > 0 {
		s := l.t("- IPs blocked / challenged most (all rules — are blocked IPs still trying?):\n",
			"- 被拦截 / 挑战最多的 IP（所有规则；被封的 IP 还在尝试吗）：\n")
		for _, f := range d.MitigatedIPs {
			s += fmt.Sprintf("  %s: %s\n", l.ip(f.Name), n(f.Count))
		}
		checks = append(checks, s)
	}
	if len(d.Blocks) > 0 {
		var bb strings.Builder
		bb.WriteString(l.t("- FlareHound blocks (attempts in the window — lift a block when attempts stop, not when it gets quiet):\n",
			"- FlareHound 设置的封禁（这段时间的尝试次数——等尝试停止再考虑解封，而不是看安静了多久）：\n"))
		for _, x := range d.Blocks {
			att := l.attempts(x, locOr(d.Loc))
			exp := l.t("permanent", "长期")
			if !x.ExpiresAt.IsZero() {
				exp = l.t("expires ", "到期 ") + x.ExpiresAt.In(locOr(d.Loc)).Format("01-02 15:04")
			}
			fmt.Fprintf(&bb, "  %s (%s): %s; %s %s; %s\n", l.ip(x.Target), x.Action, att,
				l.t("since", "始于"), x.Since.In(locOr(d.Loc)).Format("01-02 15:04"), exp)
		}
		l.expiring(&bb, d)
		checks = append(checks, bb.String())
	}
	for _, c := range d.Checkpoints {
		mark := "✓"
		if c.OriginReach > c.Max {
			mark = "⚠"
		}
		checks = append(checks, fmt.Sprintf(l.t("- %s %s: %s requests reached the origin (limit %s)\n", "- %s %s：%s 次请求打到源站（上限 %s）\n"), mark, c.Label, n(c.OriginReach), n(c.Max)))
	}
	for _, a := range d.Artifacts {
		checks = append(checks, fmt.Sprintf(l.t("- %s: %s (a Cloudflare counting artifact, not errors visitors saw)\n", "- %s：%s（Cloudflare 的统计假象，不是访客遇到的错误）\n"), a.Label, n(a.Count)))
	}
	if len(checks) > 0 {
		b.WriteString("\n" + l.t("Routine checks:\n", "例行检查：\n"))
		for _, c := range checks {
			b.WriteString(c)
		}
	}

	l.suggestions(&b, d.Suggestions)

	if d.Audit != nil {
		b.WriteString("\n")
		l.auditBody(&b, *d.Audit, false)
	}

	if a := d.Archive; a != nil && len(a.Warming) > 0 {
		var ms []string
		for _, im := range a.Warming {
			ms = append(ms, l.metricName(im))
		}
		need := a.Warming[0].Need
		fmt.Fprintf(&b, "\n"+l.t("Learning the normal level: %s — newly measured; no alerts on these until %d days of the same hour are measured (from about %s), then they switch on by themselves.\n",
			"正在学习平时水平：%s——刚开始采集；同时段满 %d 天前不报警（约 %s 起），之后自动启用。\n"),
			strings.Join(ms, l.t(", ", "、")), need, d.Window.To.Add(time.Duration(need)*24*time.Hour).In(locOr(d.Loc)).Format("01-02"))
	}
	if !d.HideStatus {
		l.statusBlock(&b, d)
	}
	if len(d.Gaps) > 0 {
		fmt.Fprintf(&b, "\n"+l.t("Some data could not be read (queries failed): %s\n", "部分数据没取到（查询失败）：%s\n"), strings.Join(d.Gaps, ", "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// attempts renders a block's attempts in the window.
func (l lang) attempts(x BlockStatus, loc *time.Location) string {
	switch {
	case x.AttemptsNA:
		return l.t("unknown", "未知")
	case x.Approx:
		s := fmt.Sprintf(l.t("≈%s (approx., from the IP board archive", "≈%s（近似值，来自 IP 榜归档"), n(x.Attempts))
		if !x.LastHour.IsZero() {
			s += fmt.Sprintf(l.t("; last on the list %s", "；最近上榜 %s"), x.LastHour.In(loc).Format("01-02 15:00"))
		}
		return s + l.t(")", "）")
	}
	return n(x.Attempts)
}

// expiringDays is the "expiring this week" horizon of the daily report.
const expiringDays = 7

// expiring lists the blocks that expire within a week, with what their
// attempts say: still knocking → consider renewing; quiet → it will be
// lifted automatically.
func (l lang) expiring(b *strings.Builder, d DailyData) {
	var out []string
	for _, x := range d.Blocks {
		if x.ExpiresAt.IsZero() || x.ExpiresAt.After(d.Window.To.Add(expiringDays*24*time.Hour)) {
			continue
		}
		when := x.ExpiresAt.In(locOr(d.Loc)).Format("01-02 15:04")
		var verdict string
		switch {
		case x.AttemptsNA:
			verdict = l.t("attempts unknown — check the blocks page before it lapses", "尝试量未知——到期前请到封锁页核对")
		case x.Attempts > 0:
			verdict = fmt.Sprintf(l.t("still trying (%s in the window) — consider renewing", "仍在尝试（这段时间 %s 次）——建议续期"), n(x.Attempts))
		default:
			verdict = l.t("quiet in the window — it will be lifted automatically", "这段时间已无尝试——到期会自动解除")
		}
		out = append(out, fmt.Sprintf(l.t("  %s (%s) expires %s: %s\n", "  %s（%s）%s 到期：%s\n"), l.ip(x.Target), x.Action, when, verdict))
	}
	if len(out) == 0 {
		return
	}
	b.WriteString(l.t("- Expiring this week:\n", "- 本周到期：\n"))
	for _, s := range out {
		b.WriteString(s)
	}
}

// impostor renders a failed crawler claim as its own line.
func (l lang) impostor(im analyze.Impostor) string {
	how := l.t("Cloudflare's verified-bot check", "Cloudflare 的正规爬虫验证")
	if im.Method == "asn" {
		how = fmt.Sprintf(l.t("%s's own networks", "%s 官方网络"), im.Crawler)
	}
	return fmt.Sprintf(l.t("FAKE CRAWLER: %q claims to be %s, but only %s of its %s requests pass %s — a scraper in disguise",
		"冒充爬虫：%q 自称 %s，但其 %[4]s 次请求中仅 %[3]s 通过%[5]s——是伪装的抓取程序"),
		clip(im.UA, 70), im.Crawler, share(im.Verified), n(im.Count), how)
}

// uaName renders a user agent; the empty UA (often the biggest bucket:
// scripts and health checks) gets an explicit label instead of a blank.
func (l lang) uaName(ua string, max int) string {
	if ua == "" {
		return l.t("(no user agent)", "（无标识）")
	}
	return clip(ua, max)
}

func (l lang) faces(b *strings.Builder, title string, cur, base []cfapi.Face, ua bool) {
	if len(cur) == 0 {
		return
	}
	old := map[string]bool{}
	for _, f := range base {
		old[f.Name] = true
	}
	fmt.Fprintf(b, "\n%s%s\n", title, l.t(":", "："))
	for i, f := range cur {
		if i >= 5 {
			break
		}
		tag := ""
		if !old[f.Name] {
			tag = l.t(" [new]", " 【新】")
		}
		name := clip(f.Name, 70)
		if ua {
			name = l.friendlyUA(f.Name)
		}
		fmt.Fprintf(b, "- %s %s%s\n", name, n(f.Count), tag)
	}
}

// coverNote says a rule already acts on a new face.
func (l lang) coverNote(c analyze.RuleCover) string {
	desc := l.t("", " ") // Chinese: a space between "#3" and the verb when there is no name
	if c.Desc != "" {
		desc = fmt.Sprintf(l.t(" %q", "「%s」"), clip(c.Desc, 40))
	}
	switch {
	case c.Action == "skip":
		return fmt.Sprintf(l.t(" — let through on purpose by skip rule #%d%s", "——被放行规则 #%d%s有意放过"), c.Pos, desc)
	case c.Partial:
		return fmt.Sprintf(l.t(" — rule #%d%s may act on it, depending on other conditions", "——规则 #%d%s视其他条件可能会拦"), c.Pos, desc)
	case c.Action == "block":
		return fmt.Sprintf(l.t(" — already blocked by rule #%d%s: these are blocked requests, they never reach the site", "——已被规则 #%d%s拦截：这些是被拦下的请求，没有进到网站"), c.Pos, desc)
	}
	return fmt.Sprintf(l.t(" — already challenged by rule #%d%s: this count includes challenged requests", "——已被规则 #%d%s挑战：这个数字包含被挑战的请求"), c.Pos, desc)
}

// simAccuracy is the fixed line on the rule simulator's predictions.
func (l lang) simAccuracy(a SimAccuracy) string {
	s := fmt.Sprintf(l.t("Rule simulator accuracy, last %d days: %d block(s) came with a prediction of how much they would newly stop, %d measured",
		"规则模拟器准不准（近 %d 天）：%d 次封禁事先预测过能多拦多少，已核对 %d 次"), a.Days, a.Predicted, a.Measured)
	if a.Measured == 0 {
		return s + l.t(" — nothing to compare yet (the hour after is not complete, or the rule records no firewall events).\n",
			"——暂时没法比（封禁后一小时的数据还没到齐，或该规则不记录防火墙事件）。\n")
	}
	s += fmt.Sprintf(l.t(" — actual vs predicted per hour: typically %+.0f%%, at most %+.0f%% (%s)",
		"——实际与预测相比（每小时）：通常偏差 %+.0f%%，最大偏差 %+.0f%%（%s）"), a.MedianDev*100, a.WorstDev*100, a.Worst)
	if a.Upper > 0 {
		s += fmt.Sprintf(l.t("; %d prediction(s) were a maximum, so coming in lower is expected", "；其中 %d 次预测是「最多」，实际偏低属正常"), a.Upper)
	}
	return s + l.t(".\n", "。\n")
}
