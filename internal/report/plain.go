package report

// plain.go is the reader-facing layer of every notification: what happened
// in plain words, what it most likely means and what to do, ahead of the
// numbers. Terms follow one glossary (docs/reports.md, "Words used"):
//
//	line crossed / 越线          → above normal / 超出平时范围
//	baseline / 基线              → normal level / 平时水平
//	dynamic                      → requests the origin has to handle / 需要源站处理的请求
//	UA                           → client / 访问者（客户端标识）
//	ASN                          → network / 来源网络
//	"137 vs 37 (×3.7)"           → "137 (previous day 37, 3.7×)" / "137（前一天 37，约 3.7 倍）"
//
// Methodology (sampling, archive, plan limits) is kept out of the lead and
// said in the system-status block, only when it changes.

import (
	"fmt"
	"strings"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/purpose"
	"github.com/playwjj/flarehound/internal/suggest"
)

// delta is a change in words: "+3.7%", "-30%", "3.7×" ("约 3.7 倍"),
// "flat" ("持平"), "new" ("新出现").
func (l lang) delta(cur, base float64) string {
	switch {
	case base == 0 && cur == 0:
		return l.t("flat", "持平")
	case base == 0:
		return l.t("new", "新出现")
	case base > 0 && cur >= 2*base:
		return fmt.Sprintf(l.t("%.1f×", "约 %.1f 倍"), cur/base)
	}
	p := (cur/base - 1) * 100
	switch {
	case p > -1 && p < 1:
		return l.t("flat", "持平")
	case p >= 10 || p <= -10:
		return fmt.Sprintf("%+.0f%%", p)
	}
	return fmt.Sprintf("%+.1f%%", p)
}

// vs is a value with what it was: "137 (previous day 37, 3.7×)",
// "137（前一天 37，约 3.7 倍）". was names the comparison window.
func (l lang) vs(cur, base int64, was string) string {
	return fmt.Sprintf(l.t("%s (%s %s, %s)", "%s（%s %s，%s）"), n(cur), was, n(base), l.delta(float64(cur), float64(base)))
}

// vsMs is vs for latencies.
func (l lang) vsMs(cur, base float64, was string) string {
	return fmt.Sprintf(l.t("%s (%s %s, %s)", "%s（%s %s，%s）"), ms(cur), was, ms(base), l.delta(cur, base))
}

// explained is one finding for the reader.
type explained struct {
	Title  string // "Origin errors up"
	Detail string // the numbers in a sentence, with what they suggest
	Action string // what to do next; "" when nothing is needed
}

// explain turns a finding into a title, a sentence and a next step. cur
// and base are the window's metrics, for the context that tells causes
// apart (errors with flat traffic point at the origin itself; volume with
// flat origin work is absorbed by the cache).
func (l lang) explain(f analyze.Finding, cur, base analyze.Metrics, was string, names, labels map[int]string) explained {
	ic, ib := int64(f.Cur), int64(f.Base)
	totalP := analyze.PctChange(float64(cur.Total), float64(base.Total))
	dynP := analyze.PctChange(float64(cur.Dynamic), float64(base.Dynamic))
	switch f.Rule {
	case analyze.RuleOrigin5xx:
		e := explained{Title: l.t("Origin errors up", "源站报错变多"),
			Detail: fmt.Sprintf(l.t("The origin answered with an error (5xx) %s times.", "源站返回错误（5xx）的次数：%s。"), l.vs(ic, ib, was)),
			Action: l.t("check the origin's error log and whether anything was deployed or reconfigured recently.",
				"查看源站错误日志，确认最近是否有部署、配置或依赖服务的变更。")}
		switch {
		case dynP >= 30:
			e.Detail += fmt.Sprintf(l.t(" Requests the origin has to handle rose %s at the same time — it may be struggling with the load.",
				"同期需要源站处理的请求涨了 %s，可能是压力过大导致。"), l.delta(float64(cur.Dynamic), float64(base.Dynamic)))
		case base.Total > 0 && totalP > -15 && totalP < 15:
			e.Detail += fmt.Sprintf(l.t(" Traffic itself barely changed (%s), so this looks like a problem in the origin itself, not a traffic surge.",
				"总流量基本没变（%s），更像是源站自身的问题，而不是被流量冲垮。"), l.delta(float64(cur.Total), float64(base.Total)))
		}
		return e
	case analyze.RuleUnreachable:
		return explained{Title: l.t("Cloudflare cannot reach the origin", "Cloudflare 连不上源站"),
			Detail: fmt.Sprintf(l.t("Cloudflare got no answer from the origin (52x errors): %s.", "Cloudflare 没能从源站拿到回应（52x 错误）的次数：%s。"), l.vs(ic, ib, was)),
			Action: l.t("make sure the origin is up and not overloaded, and that its firewall does not block Cloudflare's IPs.",
				"确认源站在线、负载正常，并检查源站防火墙没有拦截 Cloudflare 的 IP。")}
	case analyze.RuleOriginSlow:
		what := l.t("time to first byte", "首字节时间")
		if f.Subject == analyze.OriginTotal {
			what = l.t("full response time", "完整响应时间")
		}
		return explained{Title: l.t("Origin slower", "源站变慢"),
			Detail: fmt.Sprintf(l.t("The origin's %s for the slowest 5%% of requests (P95) is %s.", "源站最慢 5% 请求的%s（P95）为 %s。"), what, l.vsMs(f.Cur, f.Base, was)),
			Action: l.t("check the origin's load, slow database queries and recent deploys.", "检查源站负载、数据库慢查询和最近的部署。")}
	case analyze.RuleCollapseTotal:
		return explained{Title: l.t("Traffic dropped sharply", "流量骤降"),
			Detail: fmt.Sprintf(l.t("Total requests: %s.", "总请求 %s。"), l.vs(ic, ib, was)),
			Action: l.t("check that the site opens, then DNS, upstream services, and whether a blocking rule hits real visitors.",
				"确认网站能正常打开，再检查 DNS、上游服务，以及是否有拦截规则误伤真实访客。")}
	case analyze.RuleCollapseWorker:
		return explained{Title: fmt.Sprintf(l.t("Worker %s calls dropped sharply", "Worker %s 调用骤降"), f.Subject),
			Detail: fmt.Sprintf(l.t("Calls: %s.", "调用次数：%s。"), l.vs(ic, ib, was)),
			Action: l.t("check the Worker's routes and its latest deploy.", "检查该 Worker 的路由和最近一次部署。")}
	case analyze.RuleWorkerCallsUp:
		return explained{Title: fmt.Sprintf(l.t("Worker %s calls up", "Worker %s 调用量上涨"), f.Subject),
			Detail: fmt.Sprintf(l.t("Calls: %s.", "调用次数：%s。"), l.vs(ic, ib, was)),
			Action: l.t("see who calls it (main networks and clients below); ordinary growth needs nothing.",
				"看看是谁在调用（见下方主要来源）；如果是正常增长可以忽略。")}
	case analyze.RuleCPUUp:
		e := explained{Title: fmt.Sprintf(l.t("Worker %s runs slower per call", "Worker %s 单次运行变慢"), f.Subject),
			Detail: fmt.Sprintf(l.t("Median CPU time per call is %.1f ms (%s %.1f ms, %s).", "单次调用 CPU 耗时中位数 %.1f ms（%s %.1f ms，%s）。"),
				f.Cur, was, f.Base, l.delta(f.Cur, f.Base)),
			Action: l.t("check the latest code deploy and slower dependencies.", "检查最近的代码部署和依赖服务是否变慢。")}
		j := analyze.JudgeCPU(cur.Worker(f.Subject), base.Worker(f.Subject))
		if j.P99Known {
			e.Detail += fmt.Sprintf(l.t(" The slowest 1%% of calls (P99): %s; number of calls: %s.", "最慢 1%% 调用（P99）的耗时 %s，调用量 %s。"),
				l.pct(j.P99Pct), l.pct(j.CallsPct))
		}
		switch j.Verdict {
		case analyze.CPUMix:
			e.Detail += l.t(" The slowest calls did not change and calls fell: cheaper calls left, which moved the median — calls did not really get more expensive.",
				"最慢的那部分调用没变、调用量反而下降：是便宜的调用少了把中位数抬高，并非真的变贵。")
			e.Action = l.t("nothing for now; watch whether it persists.", "暂不需要处理，观察是否持续。")
		case analyze.CPUCostly:
			e.Detail += l.t(" The slowest calls got slower too while calls held: calls really got more expensive.",
				"最慢的那部分调用也一起变慢、调用量没跌：确实变贵了。")
		}
		return e
	case analyze.RuleDynamicUp:
		e := explained{Title: l.t("More requests reach the origin", "需要源站处理的请求变多"),
			Detail: fmt.Sprintf(l.t("Requests not served from cache (the origin or Worker has to build them): %s.", "没有命中缓存、需要源站（或 Worker）实时处理的请求：%s。"), l.vs(ic, ib, was)),
			Action: l.t("see \"Paths that reach the origin\" below for the pages that missed the cache.", "看下方「回源最多的路径」，找出是哪些页面没走缓存。")}
		if totalP < 15 {
			e.Detail += l.t(" Total traffic barely rose, so caching may have broken: a cache rule change, requests with random query strings, or a deploy.",
				"总流量没怎么涨，可能是缓存失效：缓存规则变更、带随机参数的请求，或一次部署。")
		}
		return e
	case analyze.RulePathUp:
		return explained{Title: fmt.Sprintf(l.t("More traffic on %s", "%s 访问量上涨"), clip(f.Subject, 50)),
			Detail: fmt.Sprintf(l.t("Requests: %s.", "请求数：%s。"), l.vs(ic, ib, was)),
			Action: l.t("check who is calling it (the console's drill-down shows the clients and networks).", "确认是谁在访问（控制台可下钻查看访问者和来源网络）。")}
	case analyze.RuleTotalUp:
		e := explained{Title: l.t("Traffic up", "总流量上涨"),
			Detail: fmt.Sprintf(l.t("Total requests: %s.", "总请求 %s。"), l.vs(ic, ib, was)),
			Action: l.t("see the main networks and clients below: real visitors (a campaign, a hot page) or a crawler?",
				"看下方主要来源和访问者，判断是真实访客（推广、热点）还是爬虫。")}
		if dynP < 15 {
			e.Detail += l.t(" Requests that reach the origin barely changed: the cache absorbed most of it, little pressure on the origin.",
				"需要源站处理的请求基本没变，增量大多被缓存挡住，对源站压力不大。")
			e.Action = l.t("nothing urgent; watch it.", "不紧急，观察即可。")
		}
		return e
	case analyze.RuleNewFaceUA:
		e := explained{Title: fmt.Sprintf(l.t("New client: %s", "出现新的访问者：%s"), l.friendlyUA(f.Subject)),
			Detail: fmt.Sprintf(l.t("%s requests; it was not among yesterday's top 25. Its user agent: %s", "%s 次请求，昨天还不在前 25 名。它的客户端标识：%s"),
				n(ic), l.uaName(f.Subject, 80)) + l.purposeTag(f.Purpose),
			Action: l.t("if you do not recognise it, the console shows which pages it fetched; block it there if needed.",
				"如果不认识它，可以在控制台查看它访问了哪些页面，必要时拦截。")}
		if f.Purpose != nil && f.Purpose.Trust == purpose.Verified {
			e.Action = l.t("a verified crawler; usually nothing to do.", "这是已验证的正规爬虫，通常无需处理。")
		}
		return e
	case analyze.RuleNewFaceASN:
		name := f.Subject
		if lb := labels[f.ASN]; lb != "" {
			name = clip(lb, 40) + " (" + f.Subject + ")"
		} else if nm := names[f.ASN]; nm != "" {
			name = clip(nm, 40) + " (" + f.Subject + ")"
		}
		e := explained{Title: fmt.Sprintf(l.t("New source network: %s", "出现新的来源网络：%s"), name),
			Detail: fmt.Sprintf(l.t("%s requests; it was not among yesterday's top 25.", "%s 次请求，昨天还不在前 25 名。"), n(ic)),
			Action: l.t("mostly ordinary user networks; watch it.", "多为普通用户网络，先观察。")}
		if f.ASN > 0 && suggest.Classify(f.ASN, names[f.ASN]) == suggest.Hosting {
			e.Detail += l.t(" It is a hosting / cloud network: real people rarely browse from there.", "这是机房 / 云服务器网络，真人访客很少从这里来。")
			e.Action = l.t("unless it is your own service or a partner, consider a challenge or a block (see the suggestions below).",
				"如果不是你自己的服务或合作方，可以考虑挑战或拦截（见下方处置建议）。")
		}
		return e
	}
	return explained{Title: f.Rule, Detail: f.String()}
}

// severityOrder ranks findings by consequence: outages and errors first,
// then cost, then volume, then new faces.
var severityOrder = map[string]int{
	analyze.RuleUnreachable: 0, analyze.RuleCollapseTotal: 0, analyze.RuleCollapseWorker: 0, analyze.RuleOrigin5xx: 1, analyze.RuleOriginSlow: 1,
	analyze.RuleWorkerCallsUp: 2, analyze.RuleCPUUp: 3, analyze.RuleDynamicUp: 4,
	analyze.RulePathUp: 5, analyze.RuleTotalUp: 6, analyze.RuleNewFaceASN: 7, analyze.RuleNewFaceUA: 8,
}

// leadMax is how many findings the lead explains one by one; the rest are
// listed in one line each.
const leadMax = 5

// lead writes the explained findings: title, sentence, next step, and
// the extra facts a finding carries (a rule already acting on it, the
// 52x judgement).
// ratio is the FlareHound/dashboard request ratio (0: not calibrated): a
// volume is also given as the dashboard would count it.
func (l lang) lead(b *strings.Builder, fs []analyze.Finding, cur, base analyze.Metrics, was string, ratio float64, names, labels map[int]string, covered map[string]analyze.RuleCover, unreachMin int64) {
	for i, f := range sortedFindings(fs) {
		if i == leadMax {
			b.WriteString(l.t("Also above normal:\n", "其他超出平时范围的指标：\n"))
		}
		if i >= leadMax {
			fmt.Fprintf(b, "- %s\n", l.findingLine(f, ratio, names, labels, covered))
			continue
		}
		e := l.explain(f, cur, base, was, names, labels)
		fmt.Fprintf(b, "▶ %s\n%s", e.Title, e.Detail)
		if ratio > 0 && dashTerms(f) {
			fmt.Fprintf(b, l.t(" (about %s as the Cloudflare dashboard counts)", "（按 Cloudflare 面板口径约 %s 次）"), n(int64(f.Cur/ratio)))
		}
		b.WriteString("\n")
		if c, ok := covered[f.Key()+"|"+f.Subject]; ok {
			fmt.Fprintf(b, "  %s\n", strings.TrimLeft(l.coverNote(c), " —"))
		}
		if f.Rule == analyze.RuleUnreachable {
			if c := l.unreachableAlert(cur, base, unreachMin); c != "" {
				fmt.Fprintf(b, "  %s\n", c)
			}
		}
		if e.Action != "" {
			fmt.Fprintf(b, "%s%s\n", l.t("→ Next: ", "→ 建议："), e.Action)
		}
		b.WriteString("\n")
	}
}

// dashTerms: the finding is a request count the dashboard also shows.
func dashTerms(f analyze.Finding) bool {
	switch f.Rule {
	case analyze.RuleCPUUp, analyze.RuleOrigin5xx, analyze.RuleOriginSlow, analyze.RuleUnreachable:
		return false
	}
	return f.Cur > 0
}

func sortedFindings(fs []analyze.Finding) []analyze.Finding {
	out := append([]analyze.Finding(nil), fs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && severityOrder[out[j].Rule] < severityOrder[out[j-1].Rule]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// friendlyUA names a client for a person: "Go program (Go-http-client/1.1)",
// "Chrome 130 · Windows", "crawler Googlebot", "no user agent".
func (l lang) friendlyUA(ua string) string {
	if ua == "" {
		return l.t("no user agent (scripts, health checks)", "没有标识的客户端（脚本、健康检查等）")
	}
	low := strings.ToLower(ua)
	first := ua
	if i := strings.IndexAny(ua, " ;("); i > 0 {
		first = ua[:i]
	}
	for _, p := range []struct{ marker, en, zh string }{
		{"go-http-client", "Go program", "Go 程序"},
		{"python-requests", "Python script", "Python 脚本"},
		{"python-urllib", "Python script", "Python 脚本"},
		{"aiohttp", "Python script", "Python 脚本"},
		{"httpx", "Python script", "Python 脚本"},
		{"scrapy", "Scrapy crawler", "Scrapy 爬虫"},
		{"curl/", "curl command line", "curl 命令行"},
		{"wget", "wget command line", "wget 命令行"},
		{"okhttp", "Java / Android app", "Java / 安卓程序"},
		{"apache-httpclient", "Java program", "Java 程序"},
		{"java/", "Java program", "Java 程序"},
		{"node-fetch", "Node.js program", "Node.js 程序"},
		{"axios", "Node.js program", "Node.js 程序"},
		{"undici", "Node.js program", "Node.js 程序"},
	} {
		if strings.HasPrefix(low, p.marker) || (len(p.marker) > 6 && strings.Contains(low, p.marker)) {
			return fmt.Sprintf(l.t("%s (%s)", "%s（%s）"), l.t(p.en, p.zh), clip(first, 40))
		}
	}
	for _, tok := range strings.FieldsFunc(ua, func(r rune) bool { return r == ' ' || r == ';' || r == '(' || r == ')' || r == ',' }) {
		t := strings.ToLower(tok)
		if strings.Contains(t, "bot") || strings.Contains(t, "spider") || strings.Contains(t, "crawl") {
			name, _, _ := strings.Cut(tok, "/")
			if strings.HasPrefix(name, "+http") || strings.HasPrefix(name, "http") {
				continue
			}
			return l.t("crawler ", "爬虫 ") + clip(name, 40)
		}
	}
	if !strings.HasPrefix(ua, "Mozilla/") {
		return clip(ua, 50)
	}
	platform := ""
	for _, p := range []struct{ marker, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"Windows", "Windows"},
		{"Macintosh", "macOS"}, {"CrOS", "ChromeOS"}, {"Linux", "Linux"},
	} {
		if strings.Contains(ua, p.marker) {
			platform = p.name
			break
		}
	}
	browser := ""
	for _, t := range []struct{ token, name string }{
		{"HeadlessChrome/", "headless"}, {"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"},
		{"Chrome/", "Chrome"}, {"Version/", "Safari"},
	} {
		i := strings.Index(ua, t.token)
		if i < 0 {
			continue
		}
		ver := ua[i+len(t.token):]
		if j := strings.IndexAny(ver, ". "); j > 0 {
			ver = ver[:j]
		}
		if t.name == "headless" {
			browser = l.t("headless Chrome (automation)", "无头 Chrome（自动化程序）")
		} else {
			browser = t.name + " " + ver
		}
		break
	}
	if browser == "" {
		s := l.t("incomplete browser user agent", "不完整的浏览器标识")
		if platform != "" {
			s += " · " + platform
		}
		return s + l.t(" (usually a script posing as a browser)", "（多为脚本冒充浏览器）")
	}
	if platform != "" {
		return browser + " · " + platform
	}
	return browser
}

// StatusKey is what the system-status block says, without the parts that
// change every day (archive size): the block is repeated only when this
// changes, or once a week.
func StatusKey(d DailyData) string {
	parts := []string{fmt.Sprintf("asn=%t", d.NoASN), fmt.Sprintf("fw=%t", d.FirewallNA)}
	if a := d.Archive; a != nil {
		parts = append(parts, fmt.Sprintf("long=%t", a.LongSamples >= analyze.LongBaselineMinSamples))
	}
	if c := d.Calibration; c != nil {
		parts = append(parts, "cal="+c.Verdict)
	}
	if p := d.Purpose; p != nil {
		parts = append(parts, fmt.Sprintf("purpose=%s/%d", p.Version, p.Overrides))
	}
	return strings.Join(parts, ",")
}

// statusBlock is how FlareHound itself is doing: plan limits, missing
// permissions, the archive and the counting basis. Not news — said when
// it changes (or weekly), never every day.
func (l lang) statusBlock(b *strings.Builder, d DailyData) {
	var lines []string
	if d.NoASN {
		lines = append(lines, l.t("this plan's analytics have no network (ASN) data: per-network breakdowns, new-network alerts and the \"undeclared automation\" purpose are off.",
			"当前套餐的分析数据不含来源网络（ASN）：按网络拆分、「新来源网络」提醒和「未申报自动化」判断都不可用。"))
	}
	if d.FirewallNA {
		lines = append(lines, l.t("firewall events cannot be read (plan, or the token lacks the permission): what rules block is not counted.",
			"读不到防火墙事件（套餐不支持或令牌缺少权限）：无法统计规则拦下了多少。"))
	}
	if a := d.Archive; a != nil {
		oldest := "-"
		if !a.Oldest.IsZero() {
			oldest = a.Oldest.In(locOr(d.Loc)).Format("2006-01-02")
		}
		s := fmt.Sprintf(l.t("local history: %s hourly and %s daily snapshots since %s; ", "本地历史：%s 个小时快照、%s 个日快照，始于 %s；"), n(a.Hours), n(a.Days), oldest)
		if a.LongSamples >= analyze.LongBaselineMinSamples {
			s += fmt.Sprintf(l.t("the normal level over the last 4 weeks is in use (%d samples).", "已用过去 4 周同时段作为平时水平（%d 个样本）。"), a.LongSamples)
		} else {
			s += fmt.Sprintf(l.t("the 4-week normal level is still building (%d/%d samples) — run `flarehound -backfill 28` once to fill it now.",
				"过去 4 周的平时水平还在积累（%d/%d 个样本），可运行一次 `flarehound -backfill 28` 立即补齐。"), a.LongSamples, analyze.LongBaselineMinSamples)
		}
		lines = append(lines, s)
	}
	if d.Calibration != nil {
		lines = append(lines, l.calibrationLine(*d.Calibration))
	}
	if p := d.Purpose; p != nil {
		s := fmt.Sprintf(l.t("purpose table: version %s", "访问目的对照表：%s 版"), p.Version)
		if p.Overrides > 0 {
			s += fmt.Sprintf(l.t(", %d override(s)", "，自定义 %d 条"), p.Overrides)
		}
		lines = append(lines, s+l.t(".", "。"))
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("\n" + l.t("System status (shown when it changes, and weekly):\n", "系统状态（有变化时显示，每周提醒一次）：\n"))
	for _, s := range lines {
		fmt.Fprintf(b, "- %s\n", s)
	}
}
