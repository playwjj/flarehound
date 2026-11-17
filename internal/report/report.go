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
	"github.com/playwjj/flarehound/internal/cfapi"
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
			clip(f.Subject, 80), n(cur))
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

// headline is the one-line conclusion: which lines were crossed, the
// most consequential first (drops and errors, then expensive traffic,
// then volume, then new faces).
func (l lang) headline(fs []analyze.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	order := map[string]int{
		analyze.RuleCollapseTotal: 0, analyze.RuleCollapseWorker: 0, analyze.RuleOrigin5xx: 1,
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

func (l lang) twoWindows(b *strings.Builder, cur, base analyze.Metrics, baseLabel string) {
	fmt.Fprintf(b, l.t("Numbers (%s):\n", "两窗对比（%s）：\n"), baseLabel)
	fmt.Fprintf(b, "- %s%s\n", l.t("zone requests: ", "zone 总请求："), l.change(cur.Total, base.Total))
	fmt.Fprintf(b, "- %s%s\n", l.t("dynamic: ", "dynamic："), l.change(cur.Dynamic, base.Dynamic))
	fmt.Fprintf(b, "- %s%s vs %s\n", l.t("origin 5xx: ", "源站 5xx："), n(cur.Origin5xx), n(base.Origin5xx))
	for _, w := range cur.Workers {
		bw := base.Worker(w.Name)
		fmt.Fprintf(b, l.t("- Worker %s: %s %s; CPU P50 %.1f vs %.1f ms (%s)\n", "- Worker %s：%s %s；CPU P50 %.1f vs %.1f ms（%s）\n"), w.Name,
			l.t("calls", "调用"), l.change(w.Calls, bw.Calls), w.CPUP50ms, bw.CPUP50ms,
			l.pct(analyze.PctChange(w.CPUP50ms, bw.CPUP50ms)))
	}
}

func (l lang) costLine(c analyze.Cost) string {
	ex, ch := c.ExpCur-c.ExpBase, c.CheapCur-c.CheapBase
	return fmt.Sprintf(l.t("expensive (Worker/origin) %s → %s (%s); cheap (edge cache) %s → %s (%s)",
		"昂贵部分（Worker/回源）%s → %s（%s）；便宜部分（边缘缓存）%s → %s（%s）"),
		n(c.ExpBase), n(c.ExpCur), signed(ex), n(c.CheapBase), n(c.CheapCur), signed(ch))
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
	case analyze.HypOriginFailure:
		return l.t("The origin is failing or overloaded.", "源站故障或过载。"),
			l.t("the 5xx concentrate on a single route — then it is an application bug on that route.", "5xx 集中在单一路径——那是该路由的应用缺陷。")
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
	fmt.Fprintf(&b, "FlareHound · %s — %s\n", d.Zone, head)
	fmt.Fprintf(&b, "%s\n", l.headline(d.Findings))
	fmt.Fprintf(&b, "%s %s", l.t("Window", "窗口"), l.window(d.Window, d.Loc))
	if d.Decision != state.DecAlert && !d.Since.IsZero() {
		fmt.Fprintf(&b, l.t("; episode since %s", "；本次异常始于 %s"), d.Since.In(locOr(d.Loc)).Format("01-02 15:04"))
	}
	b.WriteString("\n\n")

	b.WriteString(l.t("Lines crossed:\n", "越线：\n"))
	for _, f := range d.Findings {
		fmt.Fprintf(&b, "- %s\n", l.finding(f))
	}
	b.WriteString("\n")
	l.twoWindows(&b, d.Cur, d.Base, l.t("vs same hour yesterday", "对比昨日同时段"))
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
		for _, f := range d.Findings {
			if f.Rule != analyze.RuleNewFaceUA && f.Rule != analyze.RuleNewFaceASN {
				continue
			}
			if h, ok := a.FaceHistory[f.Subject]; ok {
				attr = append(attr, fmt.Sprintf(l.t("%s seen before: first %s, last %s, peak %s/window", "%s 曾出现过：首次 %s，最近 %s，峰值 %s/窗"),
					clip(f.Subject, 60), h.First.In(locOr(d.Loc)).Format("2006-01-02 15:04"), h.Last.In(locOr(d.Loc)).Format("01-02 15:04"), n(h.MaxCount)))
			} else {
				attr = append(attr, fmt.Sprintf(l.t("%s: never seen before in the archive", "%s：归档中首次出现"), clip(f.Subject, 60)))
			}
		}
	}
	if len(a.TopIPs) > 0 {
		attr = append(attr, l.t("top client IPs: ", "客户端 IP Top：")+faceList(a.TopIPs, 5))
	}
	if len(a.Firewall) > 0 {
		attr = append(attr, l.t("firewall events: ", "防火墙事件：")+faceList(a.Firewall, 5))
	}
	if len(a.VerifiedBots) > 0 {
		attr = append(attr, l.t("verified crawlers excluded from new faces (UA matched ASN): ", "已验明正身的爬虫（UA 与 ASN 吻合），不计新面孔：")+strings.Join(a.VerifiedBots, ", "))
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
			fmt.Fprintf(&b, l.t("- IP %s: %s requests, ~%s of the excess\n", "- IP %s：%s 次，约占增量 %s\n"), c.IP, n(c.Count), share(c.Share))
			if t, err := block.Parse("ip", c.IP); err == nil {
				fmt.Fprintf(&b, "  %s %s\n", l.t("one-click:", "一键执行："), block.Command(t, block.Block, "24h", ""))
			}
		}
	} else if d.Block.Dispersed {
		b.WriteString("\n" + l.t("Sources are dispersed (top IP < 1% of the excess): per-IP blocking will not help — act at ASN or path level (challenge).\n",
			"来源高度分散（单 IP 份额 < 1%）：逐 IP 封锁无效，应在 ASN 或路径层面处置（挑战）。\n"))
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

// BlockStatus is one active FlareHound block for the daily checkpoint.
type BlockStatus struct {
	Target     string
	Action     string
	Attempts   int64
	AttemptsNA bool
	Since      time.Time
	ExpiresAt  time.Time
}

// ArchiveInfo summarises the local archive for the daily report.
type ArchiveInfo struct {
	Hours, Days int64
	Oldest      time.Time
	LongSamples int
}

// DailyData is everything the daily report shows.
type DailyData struct {
	Zone              string
	Window            schedule.Window
	Loc               *time.Location
	Cur, Base         analyze.Metrics
	Findings          []analyze.Finding
	VerifiedBots      []string
	Cost              *analyze.Cost
	DynamicPaths      []analyze.PathDelta
	Firewall          []cfapi.Face
	FirewallNA        bool
	Checkpoints       []Checkpoint
	Artifacts         []ArtifactCount
	Suggestions       []suggest.Suggestion
	Archive           *ArchiveInfo
	Blocks            []BlockStatus
	ActiveSince       time.Time
	ActiveFingerprint string
	Gaps              []string
}

// Daily renders the daily report.
func Daily(language string, d DailyData) string {
	l := lang(language)
	var b strings.Builder
	fmt.Fprintf(&b, l.t("FlareHound daily · %s\n", "FlareHound 日报 · %s\n"), d.Zone)

	var warn []string
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
	fmt.Fprintf(&b, "%s %s\n\n", l.t("Window", "窗口"), l.window(d.Window, d.Loc))

	l.twoWindows(&b, d.Cur, d.Base, l.t("vs previous 24h", "对比前 24 小时"))
	if d.Cost != nil {
		fmt.Fprintf(&b, "- %s\n", l.costLine(*d.Cost))
	}

	if len(d.Findings) > 0 {
		b.WriteString("\n" + l.t("Lines crossed:\n", "越线：\n"))
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "- %s\n", l.finding(f))
		}
	}

	if len(d.DynamicPaths) > 0 {
		b.WriteString("\n" + l.t("Top dynamic paths:\n", "dynamic 路径 Top：\n"))
		for _, p := range d.DynamicPaths {
			fmt.Fprintf(&b, "- %s %s\n", clip(p.Path, 70), l.change(p.Cur, p.Base))
		}
	}
	l.faces(&b, l.t("Top ASNs", "ASN Top"), d.Cur.TopASN, d.Base.TopASN)
	l.faces(&b, l.t("Top user agents", "UA Top"), d.Cur.TopUA, d.Base.TopUA)
	if len(d.VerifiedBots) > 0 {
		fmt.Fprintf(&b, "- %s%s\n", l.t("verified crawlers (UA matched ASN): ", "已验明正身的爬虫："), strings.Join(d.VerifiedBots, ", "))
	}

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
	if len(d.Blocks) > 0 {
		b.WriteString(l.t("- FlareHound blocks (attempts in the window — lift a block when attempts stop, not when it gets quiet):\n",
			"- FlareHound 封锁项（窗口内尝试量——尝试停止才考虑解封，而不是看安静多久）：\n"))
		for _, x := range d.Blocks {
			att := n(x.Attempts)
			if x.AttemptsNA {
				att = l.t("n/a", "不可用")
			}
			exp := l.t("permanent", "长期")
			if !x.ExpiresAt.IsZero() {
				exp = l.t("expires ", "到期 ") + x.ExpiresAt.In(locOr(d.Loc)).Format("01-02 15:04")
			}
			fmt.Fprintf(&b, "  %s (%s): %s; %s %s; %s\n", x.Target, x.Action, att,
				l.t("since", "始于"), x.Since.In(locOr(d.Loc)).Format("01-02 15:04"), exp)
		}
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
	}
	if len(d.Gaps) > 0 {
		fmt.Fprintf(&b, "\n"+l.t("Data gaps (queries failed): %s\n", "数据缺口（查询失败）：%s\n"), strings.Join(d.Gaps, ", "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (l lang) faces(b *strings.Builder, title string, cur, base []cfapi.Face) {
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
		fmt.Fprintf(b, "- %s %s%s\n", clip(f.Name, 70), n(f.Count), tag)
	}
}
