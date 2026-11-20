package report

import (
	"fmt"
	"strings"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/purpose"
)

// PurposeData is the daily report's traffic-by-purpose section: the
// window and the same window a day earlier, classified at render time
// with the table in force (the archive keeps raw user agents only).
type PurposeData struct {
	Version             string
	Overrides           int
	Cur, Base           purpose.Facet
	CurTotal, BaseTotal int64          // zone requests of each window (the shares' denominator)
	BaseNA              bool           // the earlier window could not be read
	ASNLabels           map[int]string // operator's short names, else registered names
}

// ClassName is a purpose's display name.
func ClassName(language string, c purpose.Class) string { return lang(language).className(c) }

func (l lang) className(c purpose.Class) string {
	switch c {
	case purpose.Training:
		return l.t("training", "训练")
	case purpose.Search:
		return l.t("search indexing", "搜索索引")
	case purpose.UserAction:
		return l.t("user-triggered", "用户触发")
	case purpose.Tool:
		return l.t("fetch tools", "工具代客")
	case purpose.Mixed:
		return l.t("mixed (search + training)", "混合（搜索+训练）")
	case purpose.Undeclared:
		return l.t("undeclared automation", "未申报自动化")
	}
	return string(c)
}

// TrustName is how a label is known, for display.
func TrustName(language string, t purpose.Trust) string { return lang(language).trustName(t) }

func (l lang) trustName(t purpose.Trust) string {
	switch t {
	case purpose.Verified:
		return l.t("verified", "已验证")
	case purpose.Claimed:
		return l.t("self-declared", "自报")
	case purpose.Behaviour:
		return l.t("by traits", "按特征")
	}
	return string(t)
}

func pctOf(v, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(v) / float64(total)
}

// purposeShifts is the conclusion-line note: classes whose share moved
// by purpose.ShiftPP or more since yesterday.
func (l lang) purposeShifts(p *PurposeData) string {
	if p == nil || p.BaseNA {
		return ""
	}
	var parts []string
	for _, s := range purpose.Shifts(p.Cur, p.Base, p.CurTotal, p.BaseTotal) {
		parts = append(parts, fmt.Sprintf(l.t("%s %.0f%% → %.0f%% (%+.0f pp)", "%s %.0f%% → %.0f%%（%+.0f 个百分点）"),
			l.className(s.Class), s.BasePct, s.CurPct, s.PP()))
	}
	if len(parts) == 0 {
		return ""
	}
	return l.t("Traffic by purpose moved: ", "用途占比变化：") + strings.Join(parts, l.t("; ", "；")) + "\n"
}

// purposeSection renders "traffic by purpose".
// asnNote says that undeclared automation is not judged without ASN data;
// the daily report leaves it to its system status, which says why.
func (l lang) purposeSection(b *strings.Builder, p *PurposeData, asnNote bool) {
	if p == nil {
		return
	}
	b.WriteString("\n" + l.t("Why they come (AI training, search, …)", "访问目的（AI 训练、搜索等）"))
	if p.CurTotal > 0 {
		fmt.Fprintf(b, l.t(" — from the clients that make up %.0f%% of requests", "——基于占总请求 %.0f%% 的主要访问者"), pctOf(p.Cur.Rows, p.CurTotal))
	}
	b.WriteString(l.t(":\n", "：\n"))
	any := false
	for _, c := range purpose.Classes {
		cur, base := p.Cur.Count(c), p.Base.Count(c)
		if cur == 0 && base == 0 {
			continue
		}
		any = true
		line := fmt.Sprintf(l.t("- %s %.1f%%: %s", "- %s %.1f%%：%s 次"), l.className(c), pctOf(cur, p.CurTotal), n(cur))
		if !p.BaseNA {
			line += fmt.Sprintf(l.t(" (yesterday %.1f%%, %s)", "（昨日 %.1f%%，%s）"), pctOf(base, p.BaseTotal), l.pct(pctChange(cur, base)))
		}
		if c == purpose.Undeclared {
			line += l.t(" — browser user agents with automation traits (hosting networks, headless)", "——具自动化特征的浏览器 UA（机房网络出口、无头浏览器）")
		}
		if s := p.Cur.Stats[c]; s != nil && len(s.Actors) > 0 {
			var top []string
			for i, a := range s.Actors {
				if i >= 3 {
					break
				}
				top = append(top, l.actor(c, a, p))
			}
			line += l.t("; Top: ", "；Top：") + strings.Join(top, l.t(", ", "、"))
		}
		b.WriteString(line + "\n")
	}
	if !any {
		b.WriteString(l.t("- nothing AI-related or undeclared automation tagged in the window\n", "- 窗口内没有被标记的 AI 相关流量或未申报自动化\n"))
	}
	if asnNote && !p.Cur.HasASN {
		b.WriteString(l.t("- undeclared automation not judged: the plan exposes no ASN dimension; named classes only\n",
			"- 未申报自动化未判定：本套餐不提供 ASN 维度，本节仅含具名类别\n"))
	}
}

func pctChange(cur, base int64) float64 {
	if base == 0 {
		if cur == 0 {
			return 0
		}
		return 999
	}
	return 100 * float64(cur-base) / float64(base)
}

// actor renders one Top actor of a class: its UA (or name), volume and
// how the label is known; for undeclared automation, where it comes from.
func (l lang) actor(c purpose.Class, a purpose.Actor, p *PurposeData) string {
	s := fmt.Sprintf("%s %s", l.actorName(a), n(a.Count))
	if c != purpose.Undeclared {
		tag := l.trustName(a.Trust(c, p.Cur.HasBot))
		if a.Override {
			tag += l.t(", override", "，覆盖")
		}
		return s + fmt.Sprintf(" [%s]", tag)
	}
	var feats []string
	if asn, cnt := a.TopASN(); asn > 0 && a.Count > 0 {
		name := fmt.Sprintf("AS%d", asn)
		if lb := p.ASNLabels[asn]; lb != "" {
			name += " " + clip(lb, 20)
		}
		feats = append(feats, fmt.Sprintf("%s %.0f%%", name, pctOf(cnt, a.Count)))
	}
	if a.Traits[purpose.TraitHeadless] {
		feats = append(feats, l.t("headless", "无头浏览器"))
	}
	if len(feats) > 0 {
		s += fmt.Sprintf(l.t(" (%s)", "（%s）"), strings.Join(feats, l.t(", ", "，")))
	}
	return s
}

// purposeTag is a new user agent's purpose, after its finding.
func (l lang) purposeTag(p *purpose.Label) string {
	if p == nil {
		return ""
	}
	parts := []string{l.className(p.Class)}
	if p.Operator != "" {
		parts = append(parts, p.Operator)
	}
	parts = append(parts, l.trustName(p.Trust))
	if p.Override {
		parts = append(parts, l.t("override", "覆盖"))
	}
	return fmt.Sprintf(l.t(" [%s]", "【%s】"), strings.Join(parts, " · "))
}

// recordedFace is a new training crawler: listed, not alerted on.
func (l lang) recordedFace(f analyze.Finding) string {
	return fmt.Sprintf(l.t("new training crawler (recorded, not alerted): %q, %s requests%s", "新出现的 AI 训练爬虫（只记录、不报警）：%q，%s 次%s"),
		l.uaName(f.Subject, 70), n(int64(f.Cur)), l.purposeTag(f.Purpose))
}

// Purpose renders the traffic-by-purpose section on its own (the
// `purpose` command): the same text as in the daily report.
func Purpose(language string, p PurposeData) string {
	l := lang(language)
	var b strings.Builder
	if s := l.purposeShifts(&p); s != "" {
		b.WriteString(s)
	}
	l.purposeSection(&b, &p, true)
	return strings.TrimSpace(b.String())
}

// actorName is a compact name for an actor: the table's marker for a
// named crawler ("GPTBot"), the browser token and platform for a browser
// UA ("Chrome/157.0.0.0 (X11; Linux x86_64)"), else the clipped UA.
func (l lang) actorName(a purpose.Actor) string {
	if a.Name != "" {
		return a.Name
	}
	return l.uaName(CompactUA(a.UA), 60)
}

// CompactUA shortens a browser user agent to its browser token and
// platform; other user agents are returned as they are.
func CompactUA(ua string) string {
	if !strings.HasPrefix(ua, "Mozilla/") {
		return ua
	}
	platform := ""
	if i := strings.Index(ua, "("); i >= 0 {
		if j := strings.Index(ua[i:], ")"); j > 0 {
			platform = ua[i : i+j+1]
		}
	}
	token := ""
	for _, t := range []string{"HeadlessChrome/", "Edg/", "OPR/", "Firefox/", "Chrome/", "Version/"} {
		if i := strings.Index(ua, t); i >= 0 {
			token = ua[i:]
			if j := strings.IndexByte(token, ' '); j > 0 {
				token = token[:j]
			}
			if t == "Version/" {
				token = "Safari " + strings.TrimPrefix(token, "Version/")
			}
			break
		}
	}
	if token == "" {
		return ua
	}
	if platform != "" {
		return token + " " + platform
	}
	return token
}
