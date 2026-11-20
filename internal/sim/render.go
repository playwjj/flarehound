package sim

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func t(lang, en, zh string) string {
	if lang == "zh" {
		return zh
	}
	return en
}

// N renders a count with thousands separators.
func N(v int64) string {
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

// Pct renders a 0..1 share without rounding a real share to 0.
func Pct(f float64) string {
	p := f * 100
	switch {
	case p == 0:
		return "0%"
	case p < 0.1:
		return strconv.FormatFloat(p, 'f', 2, 64) + "%"
	case p < 10:
		return strconv.FormatFloat(p, 'f', 1, 64) + "%"
	}
	return strconv.FormatFloat(p, 'f', 0, 64) + "%"
}

// Num renders a report count: "≤ " in front of an upper bound, and the
// dashboard equivalent when calibrated.
func (r *Report) Num(v int64, lang string) string {
	s := N(v)
	if r.Upper() {
		s = "≤ " + s
	}
	if r.DashRatio > 0 && v > 0 {
		s += fmt.Sprintf(t(lang, " (≈ %s in dashboard terms)", "（≈ 面板 %s 次）"), N(int64(float64(v)/r.DashRatio)))
	}
	return s
}

// NetMark is the net new's sign: "≤" for an upper bound, "≈" otherwise.
func (r *Report) NetMark() string {
	if r.Upper() || r.NetUpper {
		return "≤"
	}
	return "≈"
}

// NetHead is the net-new figure to lead with: the window's total when the
// firewall events cover the whole window, else the per-day rate
// extrapolated from the part they cover (the covered part's own count is
// a footnote: NetFoot).
func (r *Report) NetHead(lang string) string {
	if r.NetFrom.IsZero() {
		return r.NetMark() + " " + N(r.Net)
	}
	return fmt.Sprintf(t(lang, "%s %s a day (extrapolated from the covered part)", "%s %s 次/日（按覆盖段外推）"), r.NetMark(), N(int64(r.NetPerDay())))
}

// NetFoot is the covered part's own count when the firewall events do not
// reach back over the whole window ("" otherwise).
func (r *Report) NetFoot(lang string, loc *time.Location) string {
	if r.NetFrom.IsZero() {
		return ""
	}
	if loc == nil {
		loc = time.UTC
	}
	return fmt.Sprintf(t(lang, "firewall events reach back only to %s: over %s → %s the net new is %s %s; the daily figure is that, extrapolated",
		"防火墙事件只覆盖到 %s：%s → %s 这一段的净新增为 %s %s；日值据此外推"),
		r.NetFrom.In(loc).Format("01-02 15:04"), r.NetFrom.In(loc).Format("01-02 15:04"), r.To.In(loc).Format("01-02 15:04"), r.NetMark(), N(r.Net))
}

// LabelText is the confidence label.
func LabelText(conf, lang string) string {
	switch conf {
	case Approx:
		return t(lang, "approximate (sampled data)", "近似（采样数据）")
	case ApproxJoined:
		return t(lang, "approximate (includes a cross-dataset estimate)", "近似（含数据集拼接估计）")
	case UpperBound:
		return t(lang, "upper bound (includes sub-expressions that cannot be evaluated exactly)", "上界（含不可精确评估的子表达式）")
	}
	return t(lang, "not evaluable", "不可评估")
}

// ReasonText says why a sub-expression cannot be evaluated, or how it
// was widened.
func ReasonText(it Item, lang string) string {
	switch it.Why {
	case whyField:
		return t(lang, "this field is not a dimension of Cloudflare's analytics (headers, cookies, body, scores, rates … cannot be replayed)",
			"该字段不是 Cloudflare 分析数据的维度（header、cookie、请求体、评分、速率等无法回放）")
	case whyOperator:
		return t(lang, "this operator has no analytics equivalent (regular expressions, wildcards, ranges)", "该运算符在分析数据中没有对应（正则、通配、区间）")
	case whyFunction:
		return t(lang, "functions other than starts_with/ends_with cannot be translated", "除 starts_with/ends_with 外的函数无法翻译")
	case whyList:
		return t(lang, "$list references cannot be expanded here (no access to the account's lists)", "此处无法展开 $list 引用（读不到账号列表）")
	case whyCIDR:
		return t(lang, "IP ranges (CIDR) cannot be filtered in analytics; list single addresses", "分析数据无法按网段（CIDR）过滤；请列出单个地址")
	case whyPlan:
		if it.Dim == "clientAsn" {
			return t(lang, "this zone's plan has no ASN dimension (clientAsn) — cannot be evaluated here", "该区无 ASN 维度（clientAsn），不可评估")
		}
		return fmt.Sprintf(t(lang, "this zone's plan does not expose the %s dimension — cannot be evaluated here", "该区数据不提供 %s 维度，不可评估"), it.Dim)
	case whyWildcard:
		return t(lang, "the value contains %, which analytics would read as a wildcard", "取值含 %，分析查询会把它当作通配符")
	case whyRefNeg:
		return t(lang, "the referer can only be read by its host; under a negation that widening gives neither a count nor an upper bound",
			"referer 只能按 host 评估；处于否定之下时，放宽后既不是精确值也不是上界")
	case whyRefHost:
		return t(lang, "the referer can only be read by its host, and this comparison does not pin one down", "referer 只能按 host 评估，而这个比较无法确定 host")
	case whyRefWiden:
		return fmt.Sprintf(t(lang, "the referer can only be read by its host: counted as every referer from %s (an upper bound)",
			"referer 只能按 host 评估：按来自 %s 的全部 referer 计（上界）"), it.Dim)
	case whyValue:
		return t(lang, "the value is not valid for this field", "取值与字段类型不符")
	case whyListManaged:
		return t(lang, "Cloudflare's managed lists ($cf.…) cannot be read", "Cloudflare 托管列表（$cf.…）的内容无法读取")
	case whyListAccess:
		return t(lang, "the account's lists could not be read (no account ID, or the token lacks Account → Account Filter Lists: Read)",
			"读不到账号的列表（未配置 account_id，或令牌缺少 Account → Account Filter Lists: Read）")
	case whyListMissing:
		return fmt.Sprintf(t(lang, "there is no list named %s in the account", "账号中没有名为 %s 的列表"), it.Dim)
	case whyListKind:
		return t(lang, "only IP and ASN lists are expanded (hostname and redirect lists are not)", "只展开 IP 与 ASN 列表（不展开 hostname、redirect 列表）")
	case whyListBig:
		return fmt.Sprintf(t(lang, "the list holds more than %d items", "列表超过 %d 项"), MaxListValues)
	case whyListRange:
		return t(lang, "the list holds IP ranges (CIDR), which cannot be filtered in analytics", "列表含网段（CIDR），分析数据无法按网段过滤")
	case whyBareField:
		return t(lang, "a bare field is only meaningful for booleans", "裸字段只对布尔字段有意义")
	}
	return t(lang, "cannot be translated", "无法翻译")
}

// NetWhyText says why net new is not available.
func NetWhyText(why, lang string) string {
	switch why {
	case "no_firewall":
		return t(lang, "this zone has no firewall-events dataset (plan) — net new is not available here", "该区无防火墙事件数据集（套餐限制），净新增不可用")
	case "firewall_fields":
		return t(lang, "the firewall-events dataset cannot filter on every field of this expression", "防火墙事件数据集无法按此表达式的全部字段过滤")
	case "firewall_retention":
		return t(lang, "the firewall events do not reach back into this window", "防火墙事件数据不覆盖此窗口")
	case "firewall_error":
		return t(lang, "the firewall-events query failed", "防火墙事件查询失败")
	}
	return why
}

// WarnText renders one observation.
func (r *Report) WarnText(w Warn, lang string) string {
	switch w.Code {
	case WarnNoHits:
		return t(lang, "the rule matched nothing in the window: it would have no effect", "窗口内没有任何命中：这条规则不会起作用")
	case WarnEyeball:
		return fmt.Sprintf(t(lang, "%s is a residential/mobile/backbone network and carries %s of the matches: real people browse from it — challenge, not block",
			"%s 是住宅/移动/骨干网络，占命中的 %s：有真人从这里访问——宜挑战，不宜封锁"), w.S, Pct(w.Share))
	case WarnKnown:
		return fmt.Sprintf(t(lang, "it hits a known source you registered: %s (%s in the window, ~%s a day) — exempt it (and not … contains \"%s\") or narrow the rule",
			"会波及已登记的已知来源：%s（窗口内 %s 次，约 %s 次/日）——加豁免分支（and not … contains \"%s\"）或收窄规则"),
			w.S, N(w.N), N(r.perDay(w.N)), w.S)
	case WarnBots:
		return fmt.Sprintf(t(lang, "verified bots are %s of the matches (%s): add `and not cf.client.bot` unless you mean to stop them",
			"已验证机器人占命中的 %s（%s 次）：除非有意拦它们，加上 `and not cf.client.bot`"), Pct(w.Share), N(w.N))
	case WarnTiny:
		return fmt.Sprintf(t(lang, "what it adds is %s of all traffic (under 1%%): blocking it will not change much", "新增拦截只占总量 %s（低于 1%%）：拦了作用不大"), Pct(w.Share))
	case WarnGap:
		return fmt.Sprintf(t(lang, "%s of what looked blockable is exempted by the rule itself or already stopped by existing rules", "看起来可拦的量中有 %s 被规则自身豁免或已被现有规则处理"), Pct(w.Share))
	case WarnBlockAll:
		s := t(lang, "block: people who would pass a challenge are blocked too — if real browsers may be among the matches, challenge first and watch",
			"封锁：能通过挑战的真人浏览器也会被全拦——若命中里可能有真人，先用挑战观察")
		if r.Chal.Known() {
			lo, hi := r.Chal.Range()
			s += fmt.Sprintf(t(lang, " (of the challenges these requests already met, roughly %s–%s got through — a block stops those too)",
				"（这批请求已遇到的挑战中约 %s–%s 能过——封锁会把这些也拦下）"), Pct(lo), Pct(hi))
		}
		return s
	case WarnChalRate:
		return t(lang, "challenge: ", "挑战：") + r.ChallengeText(lang)
	case WarnSkipped:
		return fmt.Sprintf(t(lang, "skip rules ahead of it let %s of its matches through first (%s) — the rule never sees them",
			"排在它前面的 skip 规则先放行了 %s 次命中（%s）——这条规则看不到它们"), N(w.N), Pct(w.Share))
	case WarnInfix:
		return t(lang, "infix starts_with/ends_with is accepted here, but Cloudflare's rules language writes it as starts_with(field, \"…\")",
			"此处接受中缀 starts_with/ends_with，但 Cloudflare 规则语言要写成 starts_with(字段, \"…\")")
	}
	return w.Code
}

func (r *Report) perDay(n int64) int64 {
	h := r.Hours()
	if h <= 0 {
		return n
	}
	return int64(float64(n) / h * 24)
}

// BotExempted is what the verified-bot exemption lets through.
func (r *Report) BotExempted() (int64, bool) {
	for _, b := range r.Branches {
		if b.Bot {
			return b.Count, true
		}
	}
	return 0, false
}

// VerdictText is the one-line conclusion.
func (r *Report) VerdictText(lang string) string {
	if !r.Evaluable {
		return fmt.Sprintf(t(lang, "Cannot be evaluated: %d sub-expression(s) have no analytics equivalent — no numbers are given.",
			"不可评估：%d 个子表达式在分析数据中没有对应——不给数。"), len(r.Unevaluable))
	}
	var b strings.Builder
	if r.HasCore {
		fmt.Fprintf(&b, t(lang, "Gross %s", "毛命中 %s"), r.Bound(r.Gross))
		if r.Exempted > 0 {
			if n, ok := r.BotExempted(); ok && n > 0 {
				fmt.Fprintf(&b, t(lang, ", of which %s exempted (verified bots %s)", "，其中豁免 %s（已验证机器人 %s）"), r.Bound(r.Exempted), r.Bound(n))
			} else {
				fmt.Fprintf(&b, t(lang, ", of which %s exempted", "，其中豁免 %s"), r.Bound(r.Exempted))
			}
		}
	} else {
		fmt.Fprintf(&b, t(lang, "Matches %s", "命中 %s"), r.Bound(r.Matched))
	}
	if r.NetKnown {
		if r.NetFrom.IsZero() {
			fmt.Fprintf(&b, t(lang, ", net new %s (%s of all traffic)", "，净新增可拦 %s（占总量 %s）"), r.NetHead(lang), Pct(r.NetShare()))
		} else {
			fmt.Fprintf(&b, t(lang, ", net new %s %s a day (extrapolated from the part the firewall events cover; %s of all traffic)",
				"，净新增可拦 %s %s 次/日（按防火墙事件覆盖段外推，占总量 %s）"), r.NetMark(), N(int64(r.NetPerDay())), Pct(r.NetShare()))
		}
	} else {
		fmt.Fprintf(&b, t(lang, ", rule matches %s (%s of all traffic); net new not available", "，规则命中 %s（占总量 %s）；净新增不可用"), r.Bound(r.Matched), Pct(r.Share(r.Matched)))
	}
	b.WriteString(t(lang, " — ", "——"))
	var rec string
	var w Warn
	for _, x := range r.Warnings {
		if x.Code == r.Verdict {
			w = x
			break
		}
	}
	switch r.Verdict {
	case WarnNoHits:
		rec = t(lang, "it would do nothing.", "这条规则不会起作用。")
	case WarnEyeball:
		rec = fmt.Sprintf(t(lang, "%s is a residential network with real people: challenge, not block.", "%s 是有真人的住宅网络：宜挑战，不宜封锁。"), w.S)
	case WarnKnown:
		rec = fmt.Sprintf(t(lang, "it hits the known source %s: exempt it or narrow the rule first.", "会波及已知来源 %s：先加豁免或收窄规则。"), w.S)
	case WarnBots:
		rec = t(lang, "verified bots are a large part of it: add `and not cf.client.bot`.", "已验证机器人占比过高：加上 `and not cf.client.bot`。")
	case WarnTiny:
		rec = t(lang, "consider a challenge, or no action.", "建议降级为挑战或不处理。")
	case WarnGap:
		rec = t(lang, "far less than it looked — weigh it on the net number.", "远少于表面量级——请按净新增判断。")
	default:
		rec = t(lang, "a measurable new stop; apply it through the usual block review.", "有可观的新增拦截；按常规封锁确认流程执行。")
	}
	b.WriteString(rec)
	return b.String()
}

// Bound renders a count, "≤ " in front of an upper bound.
func (r *Report) Bound(v int64) string {
	if r.Upper() {
		return "≤ " + N(v)
	}
	return N(v)
}

// Text is the whole report as plain text (CLI).
func (r *Report) Text(lang string, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p(t(lang, "Rule simulation — %s\n", "规则模拟 —— %s\n"), r.Zone)
	p(t(lang, "Expression: %s\n", "表达式：%s\n"), r.Expr)
	p(t(lang, "Action:     %s\n", "动作：    %s\n"), r.Action)
	p(t(lang, "Window:     %s → %s (%.0f h; the last hour is left out: data still landing)\n", "窗口：    %s → %s（%.0f 小时；最近 1 小时数据未落定，不计）\n"),
		r.From.In(loc).Format("2006-01-02 15:04"), r.To.In(loc).Format("2006-01-02 15:04 MST"), r.Hours())
	p(t(lang, "Confidence: %s\n", "置信：    %s\n"), LabelText(r.Confidence, lang))
	if !r.Evaluable {
		p("\n%s\n", r.VerdictText(lang))
		for _, it := range r.Unevaluable {
			p("  ✗ %s\n      %s\n", it.Expr, ReasonText(it, lang))
		}
		for _, w := range r.Warnings {
			p(t(lang, "  note: %s\n", "  提示：%s\n"), r.WarnText(w, lang))
		}
		return b.String()
	}
	for _, it := range r.Widened {
		p(t(lang, "  ≤ %s\n      %s\n", "  ≤ %s\n      %s\n"), it.Expr, ReasonText(it, lang))
	}
	for _, l := range r.Lists {
		p(t(lang, "  $%s expanded: %s list, %d item(s)\n", "  已展开 $%s：%s 列表，%d 项\n"), l.Name, l.Kind, l.Items)
	}

	b.WriteString(t(lang, "\n1. Gross matches\n", "\n1. 毛命中\n"))
	if r.HasCore {
		p(t(lang, "   without its exemptions: %s, %s of all traffic\n", "   不计豁免分支：%s，占总量 %s\n"), r.Num(r.Gross, lang), Pct(r.Share(r.Gross)))
	}
	p(t(lang, "   rule matches:           %s, %s of all traffic", "   规则命中：    %s，占总量 %s"), r.Num(r.Matched, lang), Pct(r.Share(r.Matched)))
	if r.DynamicKnown && r.Dynamic > 0 {
		p(t(lang, ", %s of the dynamic (origin) traffic", "，占 dynamic（回源）%s"), Pct(r.DynShare()))
	}
	p("\n")
	p(t(lang, "   zone total %s", "   该区总量 %s"), N(r.Total))
	if r.CleanEmptyUA {
		p(t(lang, " — empty-UA entries (Worker bookkeeping) left out everywhere; this rule's share of them: %s", "——空 UA 条目（Worker 内部记账）一律不计；本规则涉及 %s 条"), N(r.EmptyUA))
	}
	p("\n")
	if len(r.Days) > 0 {
		b.WriteString(t(lang, "   rule matches per day:\n", "   规则命中按天：\n"))
		for _, d := range r.Days {
			part := ""
			if d.Part {
				part = t(lang, " (part of the day)", "（不足一天）")
			}
			p("     %s  %12s%s\n", d.Date, r.Bound(d.Count), part)
		}
	}

	b.WriteString(t(lang, "\n2. Exemptions\n", "\n2. 豁免拆分\n"))
	if r.HasCore {
		p(t(lang, "   exempted by the rule itself: %s (gross − matches)\n", "   被规则自身豁免：%s（毛命中 − 规则命中）\n"), r.Bound(r.Exempted))
		for _, br := range r.Branches {
			p(t(lang, "     and not %s: %s\n", "     and not %s：%s\n"), br.Expr, r.Bound(br.Count))
		}
	} else {
		b.WriteString(t(lang, "   no top-level `and not …` branch to split out\n", "   没有可单列的顶层 `and not …` 分支\n"))
	}
	if r.BotsKnown {
		p(t(lang, "   verified bots among the matches: %s (%s)\n", "   命中中的已验证机器人：%s（%s）\n"), r.Bound(r.Bots), Pct(share(r.Bots, r.Matched)))
	}

	b.WriteString(t(lang, "\n3. Net new (the number that counts)\n", "\n3. 净新增（核心数字）\n"))
	if r.NetKnown {
		if r.NetFrom.IsZero() {
			p(t(lang, "   %s, %s of all traffic (~%s a day)\n", "   %s，占总量 %s（约 %s 次/日）\n"), r.NetHead(lang), Pct(r.NetShare()), N(int64(r.NetPerDay())))
		} else {
			p(t(lang, "   %s, %s of all traffic\n", "   %s，占总量 %s\n"), r.NetHead(lang), Pct(r.NetShare()))
			p(t(lang, "   (%s)\n", "   （%s）\n"), r.NetFoot(lang, loc))
		}
		p(t(lang, "   already stopped by existing rules: %s\n", "   已被现有规则处理：%s\n"), N(r.Handled))
		for _, h := range r.HandledBy {
			p("     %-48s %s\n", clip(h.Name, 48), N(h.Count))
		}
		if line := r.PositionText(lang); line != "" {
			p("   %s\n", line)
		}
		for _, s := range r.Skips {
			switch {
			case s.Unknown:
				p(t(lang, "     #%d %s: logs nothing and cannot be translated — not counted; net new is an upper bound\n",
					"     #%d %s：不记录日志且无法翻译——未计入；净新增为上界\n"), s.Pos, s.Label)
			case s.NoLog:
				p(t(lang, "     #%d %s: %s (logs nothing: counted from its expression)\n", "     #%d %s：%s（不记录日志：按其表达式计）\n"), s.Pos, s.Label, N(s.Count))
			default:
				p("     #%d %s: %s\n", s.Pos, s.Label, N(s.Count))
			}
		}
		if r.PositionKnown {
			b.WriteString(t(lang, "   estimate: matches come from the HTTP requests dataset, \"already stopped\" and \"skipped ahead\" from the firewall events — two datasets, sampled differently\n",
				"   估计值：命中来自 HTTP 请求数据集，已处理与前置跳过来自防火墙事件数据集——两套数据采样口径不同\n"))
		} else {
			b.WriteString(t(lang, "   estimate: matches come from the HTTP requests dataset, \"already stopped\" from the firewall events — two datasets, sampled differently; counted against the whole rule set, not this rule's position\n",
				"   估计值：命中来自 HTTP 请求数据集，已处理量来自防火墙事件数据集——两套数据采样口径不同；按全规则集口径估计，未计规则插入位置\n"))
		}
	} else {
		p("   %s\n", NetWhyText(r.NetWhy, lang))
	}

	b.WriteString(t(lang, "\n4. Composition of the matches\n", "\n4. 构成拆分\n"))
	section := func(title string, rows []Row, label func(Row) string) {
		if len(rows) == 0 {
			return
		}
		p("   %s\n", title)
		for _, x := range rows {
			p("     %-60s %12s  %s\n", clip(label(x), 60), r.Bound(x.Count), Pct(x.Share))
		}
	}
	section(t(lang, "paths:", "路径："), r.Paths, func(x Row) string { return x.Name })
	section(t(lang, "user agents:", "UA："), r.UAs, func(x Row) string {
		if x.Name == "" {
			return t(lang, "(empty UA)", "(空 UA)")
		}
		return x.Name
	})
	section(t(lang, "client IPs:", "客户端 IP："), r.IPs, func(x Row) string {
		s := x.Name
		if x.Country != "" {
			s += " [" + x.Country + "]"
		}
		if x.ASN > 0 {
			s += fmt.Sprintf(" AS%d", x.ASN)
		}
		if x.Bot {
			s += t(lang, " (verified bot)", "（已验证机器人）")
		}
		return s
	})
	section(t(lang, "countries:", "国家："), r.Countries, func(x Row) string { return x.Name })
	if !r.ASNBound {
		section(t(lang, "networks:", "网络："), r.ASNs, func(x Row) string {
			s := x.Name
			if x.Desc != "" {
				s += " " + x.Desc
			}
			if x.Network != "" {
				s += " [" + x.Network + "]"
			}
			return s
		})
	}
	if len(r.Known) > 0 {
		b.WriteString(t(lang, "   known sources (known_faces) among the matches:\n", "   命中中的已知来源（known_faces）：\n"))
		for _, k := range r.Known {
			p("     %-60s %12s\n", clip(k.Pattern, 60), r.Bound(k.Count))
		}
	}

	b.WriteString(t(lang, "\n5. Verdict\n", "\n5. 裁决\n"))
	p("   %s\n", r.VerdictText(lang))
	for _, w := range r.Warnings {
		if w.Code == r.Verdict {
			continue
		}
		p("   ! %s\n", r.WarnText(w, lang))
	}
	for _, e := range r.Errors {
		p(t(lang, "   (section failed: %s)\n", "   （部分查询失败：%s）\n"), e)
	}
	if len(r.Skipped) > 0 {
		p(t(lang, "   (left out by the %d-query budget: %s)\n", "   （超出 %d 次查询预算而略去：%s）\n"), MaxQueries, strings.Join(r.Skipped, ", "))
	}
	p(t(lang, "\n%d GraphQL queries. Sampled, aggregated analytics: the precision limit is the sampling, not a per-request replay.\n",
		"\n共 %d 次 GraphQL 查询。采样聚合数据：精度上限就是采样，不是逐请求回放。\n"), r.Queries)
	return b.String()
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// PositionText says where the draft would sit and what the skip rules
// ahead of it take ("" when the position was not considered and there is
// nothing to say).
func (r *Report) PositionText(lang string) string {
	if !r.PositionKnown {
		switch r.PositionWhy {
		case "rules_unreadable":
			return t(lang, "position not considered: the custom rules could not be read (read token needs Zone → WAF: Read)",
				"未计规则位置：读不到自定义规则（读令牌需要 Zone → WAF: Read）")
		case "no_rules":
			return t(lang, "position not considered", "未计规则位置")
		}
		return ""
	}
	how := t(lang, "where a new FlareHound rule goes: after the skip rules, ahead of the first challenge/block rule", "按 FlareHound 新规则的默认位置：skip 规则之后、第一条挑战/封锁规则之前")
	if r.PositionChosen {
		how = t(lang, "as chosen", "按指定位置")
	}
	s := fmt.Sprintf(t(lang, "position #%d (%s)", "位置 #%d（%s）"), r.Position, how)
	if r.PosBefore != "" {
		s += fmt.Sprintf(t(lang, ", before %s", "，排在 %s 之前"), r.PosBefore)
	}
	if len(r.Skips) == 0 {
		return s + t(lang, "; no skip rule ahead lets these matches through", "；前面没有放行这些命中的 skip 规则")
	}
	return s + fmt.Sprintf(t(lang, "; skip rules ahead let %s of the matches through first:", "；前面的 skip 规则先放行了 %s 次命中："), N(r.SkippedAhead))
}

// ChallengeText is the slice's challenge history as a reference range.
func (r *Report) ChallengeText(lang string) string {
	c := r.Chal
	if !c.Known() {
		return t(lang, "no challenge history for these requests in the firewall events — no pass rate to go by",
			"防火墙事件里这批请求没有挑战记录——没有通过率可参考")
	}
	lo, hi := c.Range()
	return fmt.Sprintf(t(lang, "challenges already met by these requests: %s issued, %s solved, %s passed with an earlier clearance, %s failed — roughly %s–%s got through (reference only: the firewall events hold only requests that met a challenge)",
		"这批请求已遇到的挑战：发出 %s、通过 %s、凭已有许可放行 %s、失败 %s——约 %s–%s 能过（仅作参考：防火墙事件只含遇到过挑战的请求，是有偏样本）"),
		N(c.Issued), N(c.Solved), N(c.Bypassed), N(c.Failed), Pct(lo), Pct(hi))
}
