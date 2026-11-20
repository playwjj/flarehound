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

func (l lang) change(cur, base int64) string {
	return fmt.Sprintf("%s vs %s (%s)", n(cur), n(base), l.pct(analyze.PctChange(float64(cur), float64(base))))
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
		return l.t("Zone requests ", "zone 总请求 ") + l.change(cur, base)
	case analyze.RuleDynamicUp:
		return l.t("Dynamic (uncached) responses ", "dynamic（未缓存）响应 ") + l.change(cur, base)
	case analyze.RuleOrigin5xx:
		x := "∞"
		if f.Base > 0 {
			x = fmt.Sprintf("%.1f", f.Cur/f.Base)
		}
		return fmt.Sprintf(l.t("Origin 5xx %s vs %s (×%s)", "源站 5xx %s vs %s（×%s）"), n(cur), n(base), x)
	case analyze.RuleUnreachable:
		return fmt.Sprintf(l.t("Origin UNREACHABLE: %s edge 52x answers vs %s (Cloudflare could not reach the origin)",
			"源站不可达：边缘 52x %s 次 vs %s（Cloudflare 连不上源站）"), n(cur), n(base))
	case analyze.RuleOriginSlow:
		what := l.t("Origin time-to-first-byte P95", "源站首字节 P95")
		if f.Subject == analyze.OriginTotal {
			what = l.t("Origin full-response P95", "源站完整响应 P95")
		}
		return fmt.Sprintf(l.t("%s %s vs %s (%s)", "%s %s vs %s（%s）"), what, ms(f.Cur), ms(f.Base), l.pct(f.Pct))
	case analyze.RuleCollapseTotal:
		return l.t("Zone requests COLLAPSED ", "zone 总请求塌量 ") + l.change(cur, base)
	case analyze.RuleWorkerCallsUp:
		return fmt.Sprintf(l.t("Worker %s calls ", "Worker %s 调用量 "), f.Subject) + l.change(cur, base)
	case analyze.RuleCollapseWorker:
		return fmt.Sprintf(l.t("Worker %s calls COLLAPSED ", "Worker %s 调用量塌量 "), f.Subject) + l.change(cur, base)
	case analyze.RuleCPUUp:
		return fmt.Sprintf(l.t("Worker %s CPU P50 %.1f ms vs %.1f ms (%s)", "Worker %s CPU P50 %.1f ms vs %.1f ms（%s）"),
			f.Subject, f.Cur, f.Base, l.pct(f.Pct))
	case analyze.RulePathUp:
		return fmt.Sprintf(l.t("Path rule %q ", "路径规则 %q "), f.Subject) + l.change(cur, base)
	case analyze.RuleNewFaceUA:
		return fmt.Sprintf(l.t("New user agent in Top 10: %q, %s requests (not in yesterday's Top 25)", "新面孔 UA 进入 Top 10：%q，%s 次（不在昨日 Top 25）"),
			l.uaName(f.Subject, 80), n(cur)) + l.purposeTag(f.Purpose)
	case analyze.RuleNewFaceASN:
		return fmt.Sprintf(l.t("New ASN in Top 10: %s, %s requests (not in yesterday's Top 25)", "新面孔 ASN 进入 Top 10：%s，%s 次（不在昨日 Top 25）"),
			f.Subject, n(cur))
	}
	return f.String()
}

// short is the compact form of a finding used in the headline.
func (l lang) short(f analyze.Finding) string {
	p := l.pct(f.Pct)
	switch f.Rule {
	case analyze.RuleTotalUp:
		return l.t("zone requests ", "zone 总量 ") + p
	case analyze.RuleDynamicUp:
		return "dynamic " + p
	case analyze.RuleOrigin5xx:
		return l.t("origin 5xx ", "源站 5xx ") + n(int64(f.Cur))
	case analyze.RuleUnreachable:
		return l.t("origin unreachable ", "源站不可达 ") + n(int64(f.Cur))
	case analyze.RuleOriginSlow:
		if f.Subject == analyze.OriginTotal {
			return l.t("origin response P95 ", "源站响应 P95 ") + ms(f.Cur)
		}
		return l.t("origin TTFB P95 ", "源站首字节 P95 ") + ms(f.Cur)
	case analyze.RuleCollapseTotal:
		return l.t("zone requests ", "zone 总量塌 ") + p
	case analyze.RuleWorkerCallsUp:
		return fmt.Sprintf(l.t("Worker %s calls %s", "Worker %s 调用 %s"), f.Subject, p)
	case analyze.RuleCollapseWorker:
		return fmt.Sprintf(l.t("Worker %s calls %s", "Worker %s 调用塌 %s"), f.Subject, p)
	case analyze.RuleCPUUp:
		return fmt.Sprintf("Worker %s CPU P50 %s", f.Subject, p)
	case analyze.RulePathUp:
		return fmt.Sprintf(l.t("path %s %s", "路径 %s %s"), f.Subject, p)
	case analyze.RuleNewFaceASN:
		return l.t("new ASN ", "新 ASN ") + f.Subject
	case analyze.RuleNewFaceUA:
		return l.t("new UA ", "新 UA ") + clip(f.Subject, 30)
	}
	return f.Rule
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
	if ratio > 0 && f.Rule != analyze.RuleCPUUp && f.Rule != analyze.RuleOrigin5xx &&
		f.Rule != analyze.RuleOriginSlow && f.Rule != analyze.RuleUnreachable && f.Cur > 0 {
		s += fmt.Sprintf(l.t(" (≈ %s in dashboard terms)", "（≈ 面板 %s 次）"), n(int64(f.Cur/ratio)))
	}
	return s
}

// headline is the one-line conclusion: which lines were crossed, the
// most consequential first (drops and errors, then expensive traffic,
// then volume, then new faces).
func (l lang) headline(fs []analyze.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	order := map[string]int{
		analyze.RuleUnreachable: 0, analyze.RuleCollapseTotal: 0, analyze.RuleCollapseWorker: 0, analyze.RuleOrigin5xx: 1, analyze.RuleOriginSlow: 1,
		analyze.RuleWorkerCallsUp: 2, analyze.RuleCPUUp: 3, analyze.RuleDynamicUp: 4,
		analyze.RulePathUp: 5, analyze.RuleTotalUp: 6, analyze.RuleNewFaceASN: 7, analyze.RuleNewFaceUA: 8,
	}
	sorted := append([]analyze.Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool { return order[sorted[i].Rule] < order[sorted[j].Rule] })
	const show = 4
	var parts []string
	for i, f := range sorted {
		if i == show {
			break
		}
		parts = append(parts, l.short(f))
	}
	head := strings.Join(parts, l.t(", ", "，"))
	if len(sorted) > show {
		head += fmt.Sprintf(l.t(" (+%d more)", "（另 %d 项）"), len(sorted)-show)
	}
	return head
}

func (l lang) twoWindows(b *strings.Builder, cur, base analyze.Metrics, baseLabel string, unreachMin int64) {
	fmt.Fprintf(b, l.t("Numbers (%s):\n", "两窗对比（%s）：\n"), baseLabel)
	fmt.Fprintf(b, "- %s%s\n", l.t("zone requests: ", "zone 总请求："), l.change(cur.Total, base.Total))
	fmt.Fprintf(b, "- %s%s\n", l.t("dynamic: ", "dynamic："), l.change(cur.Dynamic, base.Dynamic))
	fmt.Fprintf(b, "- %s%s vs %s%s\n", l.t("origin 5xx: ", "源站 5xx："), n(cur.Origin5xx), n(base.Origin5xx), l.errDetail(cur))
	if cur.Unreachable > 0 || base.Unreachable > 0 {
		fmt.Fprintf(b, "- %s%s vs %s%s\n", l.t("origin unreachable (edge 52x): ", "源站不可达（边缘 52x）："),
			n(cur.Unreachable), n(base.Unreachable), statusSplit(cur.UnreachableBy, l))
		if c := l.unreachableCheck(cur, base, unreachMin); c != "" {
			fmt.Fprintf(b, "  %s\n", c)
		}
	}
	if o := cur.Origin; o != nil {
		line := fmt.Sprintf(l.t("- origin P95: first byte %s, full response %s", "- 源站 P95：首字节 %s，完整响应 %s"), ms(o.TTFBP95ms), ms(o.TotalP95ms))
		if bo := base.Origin; bo != nil {
			line += fmt.Sprintf(l.t(" (was %s / %s)", "（基线 %s / %s）"), ms(bo.TTFBP95ms), ms(bo.TotalP95ms))
		}
		// Connections are mostly reused, so set-up P95s are often 0: only
		// worth a mention when they are not.
		if o.TCPP95ms > 0 || o.TLSP95ms > 0 {
			line += fmt.Sprintf(l.t("; connect TCP %s, TLS %s", "；建连 TCP %s、TLS %s"), ms(o.TCPP95ms), ms(o.TLSP95ms))
		}
		line += fmt.Sprintf(l.t("; over %s origin-answered requests\n", "；基于 %s 个回源请求\n"), n(o.Requests))
		b.WriteString(line)
	}
	for _, w := range cur.Workers {
		bw := base.Worker(w.Name)
		line := fmt.Sprintf(l.t("- Worker %s: %s %s; CPU P50 %.1f vs %.1f ms (%s)", "- Worker %s：%s %s；CPU P50 %.1f vs %.1f ms（%s）"), w.Name,
			l.t("calls", "调用"), l.change(w.Calls, bw.Calls), w.CPUP50ms, bw.CPUP50ms,
			l.pct(analyze.PctChange(w.CPUP50ms, bw.CPUP50ms)))
		if w.CPUP99ms > 0 && bw.CPUP99ms > 0 {
			line += fmt.Sprintf(l.t(", P99 %.1f vs %.1f ms (%s)", "，P99 %.1f vs %.1f ms（%s）"), w.CPUP99ms, bw.CPUP99ms,
				l.pct(analyze.PctChange(w.CPUP99ms, bw.CPUP99ms)))
		}
		b.WriteString(line + "\n")
	}
}

// metricName names a tracked metric (baseline maturity) for the reader.
func (l lang) metricName(im analyze.Maturity) string {
	switch im.Metric {
	case analyze.MetricUnreachable:
		return l.t("edge 52x (origin unreachable)", "边缘 52x（源站不可达）")
	case analyze.MetricOrigin:
		return l.t("origin latency", "源站延迟")
	case analyze.MetricCPUP99:
		return l.t("CPU P99 check of Worker ", "Worker CPU P99 辨伪 ") + im.Subject
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
		return fmt.Sprintf(l.t("check: bookkeeping background, not an outage — 522/524 are %.1f%% of it, the same order as the baseline (×%.1f), the origin keeps answering",
			"判别：记账底量，非源站故障——522/524 占 %.1f%%，与基线同量级（×%.1f），源站照常回源"), c.BookShare*100, c.Jump)
	case analyze.UnreachIncident:
		var why []string
		if c.JumpHit {
			why = append(why, fmt.Sprintf(l.t("volume ×%.1f the background", "量级为底量的 ×%.1f"), c.Jump))
		}
		if c.MixHit {
			why = append(why, fmt.Sprintf(l.t("statuses other than 522/524: %s (%.0f%%)", "非 522/524 状态 %s 次（占 %.0f%%）"), n(c.Others), (1-c.BookShare)*100))
		}
		if c.CollapseHit {
			why = append(why, fmt.Sprintf(l.t("origin-answered requests %s", "源站回源量 %s"), l.pct(c.Collapse)))
		}
		return l.t("check: departs from the 522/524 bookkeeping background — ", "判别：偏离 522/524 记账底量——") + strings.Join(why, l.t("; ", "；"))
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

// cpuCheck is the three-number check every CPU line carries: the median,
// the tail and the call count, and what they say together — so nobody has
// to redo the attribution by hand.
func (l lang) cpuCheck(f analyze.Finding, cur, base analyze.Metrics) string {
	if f.Rule != analyze.RuleCPUUp {
		return ""
	}
	j := analyze.JudgeCPU(cur.Worker(f.Subject), base.Worker(f.Subject))
	p99 := l.t("P99 not measured", "P99 未采集")
	if j.P99Known {
		p99 = "P99 " + l.pct(j.P99Pct)
	}
	s := fmt.Sprintf(l.t("check: P50 %s, %s, calls %s", "辨伪：P50 %s，%s，调用量 %s"), l.pct(j.P50Pct), p99, l.pct(j.CallsPct))
	switch j.Verdict {
	case analyze.CPUMix:
		s += l.t(" → mix change, not more expensive: the tail is flat and calls fell (the cheap calls left, the median moved)",
			" → 构成变化而非变贵：尾部持平且调用量下降（便宜调用离场，中位数被抬高）")
	case analyze.CPUCostly:
		s += l.t(" → calls really got more expensive: the tail rose with the median and calls held",
			" → 真变贵：尾部随中位数同涨且调用量未跌")
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
// " (2.1% of origin answers; 502 ×80, 504 ×40)".
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
	return l.t(" (", "（") + strings.Join(parts, l.t("; ", "；")) + l.t(")", "）")
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
	return fmt.Sprintf(l.t("real rendering (dynamic) %s → %s (%s); other cache misses (miss/bypass/expired…) %s → %s (%s); edge cache hits %s → %s (%s)",
		"真实渲染（dynamic）%s → %s（%s）；其他未命中缓存（miss/bypass/expired 等）%s → %s（%s）；边缘缓存命中 %s → %s（%s）"),
		n(c.DynBase), n(c.DynCur), l.pct(analyze.PctChange(float64(c.DynCur), float64(c.DynBase))),
		n(ob), n(oc), l.pct(analyze.PctChange(float64(oc), float64(ob))),
		n(c.CheapBase), n(c.CheapCur), l.pct(analyze.PctChange(float64(c.CheapCur), float64(c.CheapBase))))
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
		return fmt.Sprintf(l.t("Crawler/bot surge: new source %s carries ~%s of the excess.", "爬虫/机器人起量：新来源 %s 约占增量的 %s。"), clip(h.Subject, 60), share(h.Share)),
			l.t("its path mix matches normal visitors and it comes from residential/mobile networks — then it is more likely real traffic (campaign, hot content).",
				"该来源的路径分布与常态访客一致、且来自宽带/移动网络——那更可能是真实流量（推广、热点）。")
	case analyze.HypCheapVolume:
		return fmt.Sprintf(l.t("~%s of the excess is cheap edge-cached volume; the real cost impact is small.", "约 %s 的增量是边缘缓存命中的便宜量，实际成本影响小。"), share(h.Share)),
			l.t("Worker CPU, dynamic responses or origin 5xx rose as well.", "Worker CPU、dynamic 响应或源站 5xx 同步上涨。")
	case analyze.HypCacheRegress:
		return l.t("Uncached responses rose while total volume did not: a cache rule, cache-busting query strings or a deploy may have reduced cacheability.",
				"总量未涨而未缓存响应上涨：缓存规则变更、带随机参数的请求或一次部署可能降低了可缓存性。"),
			l.t("the dynamic increase is concentrated in one new source — then it is a crawler hitting uncached paths.",
				"dynamic 增量集中在单一新来源——那是爬虫在打未缓存路径。")
	case analyze.HypSlowPath:
		return fmt.Sprintf(l.t("Worker %s burns more CPU per call without more calls: likely a deploy change or a slow code path.", "Worker %s 调用量平稳但单次 CPU 上涨：疑为部署变更或慢路径。"), h.Subject),
			l.t("the request mix shifted to heavier paths (see top dynamic paths).", "请求构成转向了更重的路径（见 dynamic 路径 Top）。")
	case analyze.HypCPUMix:
		return fmt.Sprintf(l.t("Worker %s: the request mix changed, the cost did not — CPU P50 rose while P99 stayed about flat and calls fell. Cheap calls left (e.g. a flood receding) and the median moved up. Reported at low severity.",
				"Worker %s：构成变化而非变贵——CPU P50 上涨，但 P99 基本持平、调用量下降。便宜调用离场（如洪水退潮），中位数被抬高。按低严重度报告。"), h.Subject),
			l.t("P99 rises in the next rounds too, or calls recover while P50 stays high — then calls really got more expensive.",
				"后续几轮 P99 也上涨，或调用量回升而 P50 仍高——那就是真变贵。")
	case analyze.HypCPUCostly:
		return fmt.Sprintf(l.t("Worker %s calls really got more expensive: CPU P50 and P99 rose together while calls held — a code change, a slower dependency or heavier requests.",
				"Worker %s 单次调用真变贵：CPU P50 与 P99 同涨且调用量未跌——疑为代码变更、依赖变慢或请求变重。"), h.Subject),
			l.t("the rise lines up with a shift to heavier paths (see top dynamic paths) and no deploy — then it is the load, not the code.",
				"上涨与请求转向更重的路径同时发生（见 dynamic 路径 Top）且无部署——那是负载而非代码。")
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
		return l.t("The origin is slowing under more work: more uncached requests reach it at the same time (see dynamic paths and new faces).",
				"源站在更多负载下变慢：同时段有更多未缓存请求打到源站（见 dynamic 路径与新面孔）。"),
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
			l.t("the origin's work shifted to a heavier path (see origin work by path) — then it is that route, not the machine.", "回源请求转向了更重的路径（见回源请求按路径）——那是该路由的问题，而非整机。")
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
		return l.t("high", "高")
	case analyze.Medium:
		return l.t("medium", "中")
	}
	return l.t("low", "低")
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

// Intraday renders an intraday alert / escalation / recovery message.
func Intraday(language string, d IntradayData) string {
	l := lang(language)
	if d.Decision == state.DecRecovered {
		return fmt.Sprintf(l.t("FlareHound · %s recovered — back to baseline for consecutive rounds (last window %s).", "FlareHound · %s 已恢复——连续多轮回到基线（最近窗口 %s）。"),
			d.Zone, l.window(d.Window, d.Loc))
	}
	var b strings.Builder
	head := map[state.Decision]string{
		state.DecAlert:    l.t("anomaly", "异常"),
		state.DecChanged:  l.t("anomaly changed (new signal)", "异常变化（出现新信号）"),
		state.DecEscalate: l.t("anomaly ESCALATED", "异常升级"),
	}[d.Decision]
	if d.Severity.Level == analyze.SevLow && d.Decision == state.DecAlert {
		head = l.t("low severity: edge-absorbed flood", "低严重度：边缘吸收的流量洪水")
		if d.Severity.Kind == analyze.CPUMixKind {
			head = l.t("low severity: Worker CPU mix change", "低严重度：Worker CPU 构成变化")
		}
	}
	fmt.Fprintf(&b, "FlareHound · %s — %s\n", d.Zone, head)
	if d.Severity.Kind == analyze.EdgeAbsorbed {
		fmt.Fprintf(&b, l.t("The extra traffic is absorbed at the edge: real rendering %s, CPU and origin errors unchanged — no pressure on the origin or Worker rendering. Watch it, no action needed.\n",
			"增量在边缘被吸收：真实渲染 %s，CPU 与源站错误未越线——源站与 Worker 渲染无压力。观察即可，无需处置。\n"), l.pct(d.Severity.DynPct))
	}
	fmt.Fprintf(&b, "%s\n", l.headline(d.Findings))
	fmt.Fprintf(&b, "%s %s", l.t("Window", "窗口"), l.window(d.Window, d.Loc))
	if d.Decision != state.DecAlert && !d.Since.IsZero() {
		fmt.Fprintf(&b, l.t("; episode since %s", "；本次异常始于 %s"), d.Since.In(locOr(d.Loc)).Format("01-02 15:04"))
	}
	b.WriteString("\n\n")

	b.WriteString(l.t("Lines crossed:\n", "越线：\n"))
	for _, f := range d.Findings {
		fmt.Fprintf(&b, "- %s\n", l.findingLine(f, d.DashRatio, d.Attr.ASNNames, d.Attr.ASNLabels, d.Attr.Covered))
		if c := l.cpuCheck(f, d.Cur, d.Base); c != "" {
			fmt.Fprintf(&b, "  %s\n", c)
		}
		if f.Rule == analyze.RuleUnreachable {
			if c := l.unreachableAlert(d.Cur, d.Base, d.UnreachableMin); c != "" {
				fmt.Fprintf(&b, "  %s\n", c)
			}
		}
	}
	b.WriteString("\n")
	l.twoWindows(&b, d.Cur, d.Base, l.t("vs same hour yesterday", "对比昨日同时段"), d.UnreachableMin)
	if d.Long != nil {
		fmt.Fprintf(&b, l.t("- 4-week same-hour median (%d samples): requests %s, dynamic %s, origin 5xx %s — every volume line above also crossed this baseline\n",
			"- 近 4 周同时段中位数（%d 个样本）：总请求 %s，dynamic %s，源站 5xx %s——上述量类越线均已对此基线复核\n"),
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
			ps = append(ps, fmt.Sprintf("%s %s (%s %s)", clip(p.Path, 60), n(p.Cur), l.t("was", "昨"), n(p.Base)))
		}
		attr = append(attr, l.t("top dynamic paths: ", "dynamic 路径 Top：")+strings.Join(ps, ", "))
	}
	keys := make([]string, 0, len(a.FacePaths))
	for k := range a.FacePaths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attr = append(attr, fmt.Sprintf(l.t("%s hits: %s", "%s 主要路径：%s"), clip(k, 60), faceList(a.FacePaths[k], 3)))
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
				attr = append(attr, fmt.Sprintf(l.t("%s seen before: first %s, last %s, peak %s/window", "%s 曾出现过：首次 %s，最近 %s，峰值 %s/窗"),
					clip(f.Subject, 60), h.First.In(locOr(d.Loc)).Format("2006-01-02 15:04"), h.Last.In(locOr(d.Loc)).Format("01-02 15:04"), n(h.MaxCount)))
			} else if !young {
				attr = append(attr, fmt.Sprintf(l.t("%s: never seen before in the archive", "%s：归档中首次出现"), clip(f.Subject, 60)))
			}
		}
		if young && hasNew {
			attr = append(attr, fmt.Sprintf(l.t("first-seen not judged: the archive covers only %d day(s) (needs %d; run -backfill 28 to fill it now)",
				"不判断「首次出现」：归档仅覆盖 %d 天（需 %d 天；可用 -backfill 28 立即补齐）"), a.ArchiveDays, analyze.FaceHistoryMinDays))
		}
	}
	for _, im := range a.Impostors {
		attr = append(attr, l.impostor(im))
	}
	if len(a.Origin5xxPaths) > 0 {
		attr = append(attr, l.t("origin 5xx by path: ", "源站 5xx 按路径：")+faceList(a.Origin5xxPaths, 5))
	}
	if len(a.OriginPaths) > 0 {
		attr = append(attr, l.t("origin work by path: ", "回源请求按路径：")+faceList(a.OriginPaths, 5))
	}
	if len(a.TopIPs) > 0 {
		attr = append(attr, l.t("top client IPs: ", "客户端 IP Top：")+l.ipList(a.TopIPs, 5))
	}
	if len(a.Firewall) > 0 {
		attr = append(attr, l.t("firewall events: ", "防火墙事件：")+faceList(a.Firewall, 5))
	}
	if len(a.VerifiedBots) > 0 {
		attr = append(attr, l.t("verified crawlers excluded from new faces: ", "已验明正身的爬虫，不计新面孔：")+strings.Join(a.VerifiedBots, ", "))
	}
	if len(a.Unsettled) > 0 {
		attr = append(attr, l.t("withheld, data still arriving: ", "数据未落定、暂不报：")+strings.Join(a.Unsettled, ", "))
	}
	if len(attr) > 0 {
		b.WriteString("\n" + l.t("Attribution:\n", "归因拆分：\n"))
		for _, s := range attr {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}

	if len(d.Hypotheses) > 0 {
		b.WriteString("\n" + l.t("Hypotheses:\n", "机制假设：\n"))
		for _, h := range d.Hypotheses {
			claim, fals := l.hypothesis(h)
			fmt.Fprintf(&b, "- [%s] %s\n", l.confidence(h.Confidence), claim)
			if fals != "" {
				fmt.Fprintf(&b, "  %s %s\n", l.t("Falsified if", "证伪点："), fals)
			}
		}
	} else {
		b.WriteString("\n" + l.t("Not enough evidence for a mechanism claim — numbers only.\n", "证据不足，只报数，不下机制结论。\n"))
	}

	if len(d.Block.Candidates) > 0 {
		b.WriteString("\n" + l.t("Block candidates:\n", "封锁候选：\n"))
		for _, c := range d.Block.Candidates {
			fmt.Fprintf(&b, l.t("- IP %s: %s requests, ~%s of the excess\n", "- IP %s：%s 次，约占增量 %s\n"), l.ip(c.IP), n(c.Count), share(c.Share))
			if t, err := block.Parse("ip", c.IP); err == nil {
				fmt.Fprintf(&b, "  %s %s\n", l.t("one-click:", "一键执行："), block.Command(t, block.Block, "24h", ""))
			}
		}
	} else if d.Block.Dispersed {
		b.WriteString("\n" + l.t("Sources are dispersed (top blockable IP < 1% of the excess): per-IP blocking will not help — act at ASN or path level (challenge).\n",
			"来源高度分散（可封 IP 中最大份额 < 1%）：逐 IP 封锁无效，应在 ASN 或路径层面处置（挑战）。\n"))
	}
	if len(d.Block.Excluded) > 0 {
		b.WriteString("\n" + l.t("Concentrated but NOT blockable:\n", "来源集中但不可封：\n"))
		for _, c := range d.Block.Excluded {
			if c.Cloudflare {
				fmt.Fprintf(&b, l.t("- IP %s: %s requests, ~%s of the excess — Cloudflare's own address (%s). This is Worker egress: a Worker (yours, or another zone's) fetching this site. Find the calling Worker; blocking would cut off your own services.\n",
					"- IP %s：%s 次，约占增量 %s——Cloudflare 自有地址（%s）。这是 Worker 出口：某个 Worker（你自己的或其他 zone 的）在调用本站。应去找调用方 Worker；封它会切断自家服务。\n"),
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
}

// Daily renders the daily report.
func Daily(language string, d DailyData) string {
	l := lang(language)
	var b strings.Builder
	fmt.Fprintf(&b, l.t("FlareHound daily · %s\n", "FlareHound 日报 · %s\n"), d.Zone)

	var warn []string
	if len(d.BlockEffects) > 0 {
		b.WriteString(l.t("- Blocks made in the window and what they did (the hour before vs the hour after):\n",
			"- 窗口内新增封禁及效果（封前一小时 vs 封后一小时）：\n"))
		for _, x := range d.BlockEffects {
			fmt.Fprintf(&b, l.t("  %s (%s, %s): %s\n", "  %s（%s，%s）：%s\n"), x.Target, x.Action, x.At.In(locOr(d.Loc)).Format("01-02 15:04"), x.Verdict)
		}
	}
	if a := d.SimAccuracy; a != nil && a.Predicted > 0 {
		b.WriteString(l.simAccuracy(*a))
	}
	for _, c := range d.Checkpoints {
		if c.OriginReach > c.Max {
			warn = append(warn, c.Label)
		}
	}
	switch {
	case len(d.Findings) == 0 && len(warn) == 0:
		b.WriteString(l.t("All clear: no alert line crossed, all checkpoints within limits.\n", "一切正常：无越线，固定检查点全部在限内。\n"))
	case len(d.Findings) > 0:
		fmt.Fprintf(&b, l.t("%d line(s) crossed — %s\n", "%d 条线越线——%s\n"), len(d.Findings), l.headline(d.Findings))
	default:
		fmt.Fprintf(&b, l.t("Checkpoint over limit: %s\n", "检查点超限：%s\n"), strings.Join(warn, ", "))
	}
	b.WriteString(l.purposeShifts(d.Purpose))
	fmt.Fprintf(&b, "%s %s\n\n", l.t("Window", "窗口"), l.window(d.Window, d.Loc))

	l.twoWindows(&b, d.Cur, d.Base, l.t("vs previous 24h", "对比前 24 小时"), d.UnreachableMin)
	if d.Cost != nil {
		fmt.Fprintf(&b, "- %s\n", l.costLine(*d.Cost))
	}

	if len(d.Findings) > 0 {
		b.WriteString("\n" + l.t("Lines crossed:\n", "越线：\n"))
		ratio := 0.0
		if d.Calibration != nil {
			ratio = d.Calibration.Requests
		}
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "- %s\n", l.findingLine(f, ratio, d.ASNNames, d.ASNLabels, d.Covered))
			if c := l.cpuCheck(f, d.Cur, d.Base); c != "" {
				fmt.Fprintf(&b, "  %s\n", c)
			}
			if f.Rule == analyze.RuleUnreachable {
				if c := l.unreachableAlert(d.Cur, d.Base, d.UnreachableMin); c != "" {
					fmt.Fprintf(&b, "  %s\n", c)
				}
			}
		}
	}

	if len(d.DynamicPaths) > 0 {
		b.WriteString("\n" + l.t("Top dynamic paths:\n", "dynamic 路径 Top：\n"))
		for _, p := range d.DynamicPaths {
			fmt.Fprintf(&b, "- %s %s\n", clip(p.Path, 70), l.change(p.Cur, p.Base))
		}
	}
	if d.NoASN {
		b.WriteString("\n" + l.t("ASN breakdown: not available on this plan (no clientAsn in analytics); new-ASN detection is off.\n",
			"ASN 拆分：本套餐分析数据不提供 clientAsn，新面孔 ASN 检测已关闭。\n"))
	}
	l.faces(&b, l.t("Top ASNs", "ASN Top"), d.Cur.TopASN, d.Base.TopASN, false)
	l.faces(&b, l.t("Top user agents", "UA Top"), d.Cur.TopUA, d.Base.TopUA, true)
	if len(d.VerifiedBots) > 0 {
		fmt.Fprintf(&b, "- %s%s\n", l.t("verified crawlers: ", "已验明正身的爬虫："), strings.Join(d.VerifiedBots, ", "))
	}
	for _, im := range d.Impostors {
		fmt.Fprintf(&b, "- %s\n", l.impostor(im))
	}
	for _, f := range d.RecordedFaces {
		fmt.Fprintf(&b, "- %s\n", l.recordedFace(f))
	}
	l.purposeSection(&b, d.Purpose)

	b.WriteString("\n" + l.t("Checkpoints:\n", "固定检查点：\n"))
	switch {
	case d.FirewallNA:
		b.WriteString(l.t("- firewall events: unavailable (plan or token permission)\n", "- 防火墙事件：不可用（套餐或 Token 权限）\n"))
	case len(d.Firewall) == 0:
		b.WriteString(l.t("- firewall events: none\n", "- 防火墙事件：无\n"))
	default:
		b.WriteString(l.t("- firewall events by rule (attempts — the basis for lifting a block):\n", "- 按规则的防火墙事件（尝试量——解封以尝试量为准）：\n"))
		for _, f := range d.Firewall {
			fmt.Fprintf(&b, "  %s: %s\n", f.Name, n(f.Count))
		}
	}
	if len(d.MitigatedIPs) > 0 {
		b.WriteString(l.t("- IPs most often blocked/challenged (all rules; are blocked IPs still knocking?):\n",
			"- 被拦截 / 挑战最多的 IP（所有规则；被封的 IP 还在敲门吗）：\n"))
		for _, f := range d.MitigatedIPs {
			fmt.Fprintf(&b, "  %s: %s\n", l.ip(f.Name), n(f.Count))
		}
	}
	if len(d.Blocks) > 0 {
		b.WriteString(l.t("- FlareHound blocks (attempts in the window — lift a block when attempts stop, not when it gets quiet):\n",
			"- FlareHound 封锁项（窗口内尝试量——尝试停止才考虑解封，而不是看安静多久）：\n"))
		for _, x := range d.Blocks {
			att := l.attempts(x, locOr(d.Loc))
			exp := l.t("permanent", "长期")
			if !x.ExpiresAt.IsZero() {
				exp = l.t("expires ", "到期 ") + x.ExpiresAt.In(locOr(d.Loc)).Format("01-02 15:04")
			}
			fmt.Fprintf(&b, "  %s (%s): %s; %s %s; %s\n", l.ip(x.Target), x.Action, att,
				l.t("since", "始于"), x.Since.In(locOr(d.Loc)).Format("01-02 15:04"), exp)
		}
		l.expiring(&b, d)
	}
	for _, c := range d.Checkpoints {
		mark := "✓"
		if c.OriginReach > c.Max {
			mark = "⚠"
		}
		fmt.Fprintf(&b, l.t("- %s %s origin reach %s (max %s)\n", "- %s %s 源站到达 %s（上限 %s）\n"), mark, c.Label, n(c.OriginReach), n(c.Max))
	}
	for _, a := range d.Artifacts {
		fmt.Fprintf(&b, l.t("- %s: %s (accounting artifact, not visitor errors)\n", "- %s：%s（记账假象，非访客错误）\n"), a.Label, n(a.Count))
	}

	l.suggestions(&b, d.Suggestions)

	if d.Audit != nil {
		b.WriteString("\n")
		l.auditBody(&b, *d.Audit, false)
	}

	if !d.ActiveSince.IsZero() {
		fmt.Fprintf(&b, "\n"+l.t("Intraday anomaly still open since %s: %s\n", "日内异常仍在持续，始于 %s：%s\n"),
			d.ActiveSince.In(locOr(d.Loc)).Format("01-02 15:04"), d.ActiveFingerprint)
	}
	if a := d.Archive; a != nil {
		long := fmt.Sprintf(l.t("long baseline active (%d samples)", "长基线已启用（%d 个样本）"), a.LongSamples)
		if a.LongSamples < analyze.LongBaselineMinSamples {
			long = fmt.Sprintf(l.t("long baseline at %d/%d samples (run with -backfill 28 to fill it now)", "长基线样本 %d/%d（可用 -backfill 28 立即补齐）"),
				a.LongSamples, analyze.LongBaselineMinSamples)
		}
		oldest := "-"
		if !a.Oldest.IsZero() {
			oldest = a.Oldest.In(locOr(d.Loc)).Format("2006-01-02")
		}
		fmt.Fprintf(&b, "\n"+l.t("Archive: %s hourly + %s daily snapshots since %s; %s\n", "归档：%s 个小时快照 + %s 个日快照，始于 %s；%s\n"),
			n(a.Hours), n(a.Days), oldest, long)
		if len(a.Warming) > 0 {
			var ms []string
			for _, im := range a.Warming {
				ms = append(ms, l.metricName(im))
			}
			need := a.Warming[0].Need
			fmt.Fprintf(&b, l.t("Baseline accumulating: %s — newly measured; these lines stay quiet until %d days of the same hour are measured (from about %s), then take over on their own.\n",
				"基线积累中：%s——新近开始采集；同时段实测满 %d 天前这些线不报警（约 %s 起），之后自动按基线判别。\n"),
				strings.Join(ms, l.t(", ", "、")), need, d.Window.To.Add(time.Duration(need)*24*time.Hour).In(locOr(d.Loc)).Format("01-02"))
		}
	}
	if d.Calibration != nil {
		fmt.Fprintf(&b, "\n%s\n", l.calibrationLine(*d.Calibration))
	}
	if len(d.Gaps) > 0 {
		fmt.Fprintf(&b, "\n"+l.t("Data gaps (queries failed): %s\n", "数据缺口（查询失败）：%s\n"), strings.Join(d.Gaps, ", "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// attempts renders a block's attempts in the window.
func (l lang) attempts(x BlockStatus, loc *time.Location) string {
	switch {
	case x.AttemptsNA:
		return l.t("n/a", "不可用")
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
			verdict = fmt.Sprintf(l.t("still knocking (%s in the window) — consider renewing", "仍在敲门（窗口内 %s 次）——建议续期"), n(x.Attempts))
		default:
			verdict = l.t("quiet in the window — it will be lifted automatically", "窗口内已无尝试——到期将自动解除")
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
	how := l.t("Cloudflare's verified-bot check", "Cloudflare 已验证机器人分类")
	if im.Method == "asn" {
		how = fmt.Sprintf(l.t("%s's own ASNs", "%s 官方 ASN"), im.Crawler)
	}
	return fmt.Sprintf(l.t("IMPOSTOR: %q claims to be %s, but only %s of its %s requests pass %s — a disguised scraper",
		"冒充爬虫：%q 自称 %s，但其 %[4]s 次请求中仅 %[3]s 通过%[5]s——伪装的抓取器"),
		clip(im.UA, 70), im.Crawler, share(im.Verified), n(im.Count), how)
}

// uaName renders a user agent; the empty UA (often the biggest bucket:
// scripts and health checks) gets an explicit label instead of a blank.
func (l lang) uaName(ua string, max int) string {
	if ua == "" {
		return l.t("(empty UA)", "(空 UA)")
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
	fmt.Fprintf(b, "\n%s:\n", title)
	for i, f := range cur {
		if i >= 5 {
			break
		}
		tag := ""
		if !old[f.Name] {
			tag = l.t(" [new]", " [新]")
		}
		name := clip(f.Name, 70)
		if ua {
			name = l.uaName(f.Name, 70)
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
		return fmt.Sprintf(l.t(" — let through by skip rule #%d%s", "——被放行规则 #%d%s放过"), c.Pos, desc)
	case c.Partial:
		return fmt.Sprintf(l.t(" — rule #%d%s may act on it, depending on other conditions", "——规则 #%d%s视其他条件可能拦截"), c.Pos, desc)
	case c.Action == "block":
		return fmt.Sprintf(l.t(" — already blocked by rule #%d%s: this volume is blocked requests", "——已被规则 #%d%s拦截：此量为被拦下的请求"), c.Pos, desc)
	}
	return fmt.Sprintf(l.t(" — already challenged by rule #%d%s: this volume includes challenged requests", "——已被规则 #%d%s质询：此量包含被质询的请求"), c.Pos, desc)
}

// simAccuracy is the fixed line on the rule simulator's predictions.
func (l lang) simAccuracy(a SimAccuracy) string {
	s := fmt.Sprintf(l.t("- Rule simulator, last %d days: %d block(s) confirmed with a net-new prediction, %d measured",
		"- 规则模拟器，近 %d 天：%d 次封锁带净新增预测，%d 次已计量"), a.Days, a.Predicted, a.Measured)
	if a.Measured == 0 {
		return s + l.t(" — nothing to compare yet (the hour after has not settled, or the rule has no firewall events).\n",
			"——尚无可比数据（封后一小时未落定，或该规则无防火墙事件）。\n")
	}
	s += fmt.Sprintf(l.t(" — actual vs predicted per hour: median %+.0f%%, widest %+.0f%% (%s)",
		"——实际对比预测（每小时）：中位偏差 %+.0f%%，最大偏差 %+.0f%%（%s）"), a.MedianDev*100, a.WorstDev*100, a.Worst)
	if a.Upper > 0 {
		s += fmt.Sprintf(l.t("; %d prediction(s) were upper bounds, so a shortfall there is expected", "；其中 %d 次预测为上界，实际偏低属预期"), a.Upper)
	}
	return s + l.t(".\n", "。\n")
}
