package report

// HTML renderings for email (v1.2). Email-safe on purpose: tables and
// inline styles only, no scripts, no external assets, no CSS classes —
// clients strip <style> blocks and block remote content. Charts arrive as
// inline images referenced by cid:<name>. Everything that comes from
// traffic (user agents, paths, rule names) is escaped.

import (
	"fmt"
	"html"
	"strings"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/state"
)

const (
	cInk    = "#111827"
	cMuted  = "#6b7280"
	cLine   = "#e5e7eb"
	cBg     = "#f3f4f6"
	cRed    = "#dc2626"
	cAmber  = "#d97706"
	cGreen  = "#059669"
	cBlue   = "#2563eb"
	cOrange = "#ea580c"
	cGrayBr = "#9ca3af"
)

// Chart is an inline image an HTML report shows.
type Chart struct {
	CID     string
	Caption string
}

func esc(s string) string { return html.EscapeString(s) }

func page(title, accent, body string) string {
	return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + esc(title) + `</title></head>` +
		`<body style="margin:0;padding:0;background:` + cBg + `;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;color:` + cInk + `">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:` + cBg + `"><tr><td align="center" style="padding:16px 8px">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:720px;background:#ffffff;border-radius:8px;border-top:4px solid ` + accent + `">` +
		`<tr><td style="padding:20px 24px">` + body + `</td></tr></table>` +
		`<div style="color:` + cMuted + `;font-size:12px;padding:12px">FlareHound — read-only watchdog. Numbers are Cloudflare adaptive analytics.</div>` +
		`</td></tr></table></body></html>`
}

func h2(s string) string {
	return `<div style="font-size:13px;font-weight:600;color:` + cMuted + `;text-transform:uppercase;letter-spacing:.04em;margin:22px 0 8px">` + esc(s) + `</div>`
}

func pctColor(p float64, upIsBad bool) string {
	switch {
	case p >= 999:
		return cRed
	case p > 15 && upIsBad, p < -15 && !upIsBad:
		return cRed
	case p > 15, p < -15:
		return cAmber
	}
	return cMuted
}

func (l lang) tile(label string, cur, base int64, upIsBad bool) string {
	p := analyze.PctChange(float64(cur), float64(base))
	return `<td style="padding:10px 12px;border:1px solid ` + cLine + `;border-radius:6px;vertical-align:top">` +
		`<div style="font-size:12px;color:` + cMuted + `">` + esc(label) + `</div>` +
		`<div style="font-size:22px;font-weight:600;margin-top:2px">` + n(cur) + `</div>` +
		`<div style="font-size:12px;color:` + pctColor(p, upIsBad) + `">` + esc(l.delta(float64(cur), float64(base))) + " · " + esc(l.t("was ", "之前 ")) + n(base) + `</div></td>`
}

func (l lang) tiles(cur, base analyze.Metrics) string {
	var b strings.Builder
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="6"><tr>`)
	b.WriteString(l.tile(l.t("Total requests", "总请求"), cur.Total, base.Total, false))
	b.WriteString(l.tile(l.t("Reach the origin (not cached)", "需源站处理（未缓存）"), cur.Dynamic, base.Dynamic, true))
	b.WriteString(l.tile(l.t("Origin errors (5xx)", "源站报错（5xx）"), cur.Origin5xx, base.Origin5xx, true))
	if cur.Unreachable > 0 || base.Unreachable > 0 {
		b.WriteString(l.tile(l.t("Origin unreachable (52x)", "连不上源站（52x）"), cur.Unreachable, base.Unreachable, true))
	}
	b.WriteString(`</tr></table>`)
	if len(cur.Workers) > 0 {
		b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="6"><tr>`)
		for _, w := range cur.Workers {
			bw := base.Worker(w.Name)
			b.WriteString(l.tile("Worker "+w.Name+l.t(" calls", " 调用"), w.Calls, bw.Calls, false))
		}
		b.WriteString(`</tr></table>`)
	}
	return b.String()
}

func charts(cs []Chart) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(`<div style="margin:10px 0"><img src="cid:` + esc(c.CID) + `" alt="` + esc(c.Caption) + `" width="672" style="width:100%;max-width:672px;height:auto;border:1px solid ` + cLine + `;border-radius:6px">` +
			`<div style="font-size:12px;color:` + cMuted + `;margin-top:4px">` + esc(c.Caption) + `</div></div>`)
	}
	return b.String()
}

// costBar is the three-band split as one stacked bar plus a legend.
func (l lang) costBar(c analyze.Cost) string {
	total := c.ExpCur + c.CheapCur
	if total <= 0 {
		return ""
	}
	seg := func(v int64, color string) string {
		w := float64(v) / float64(total) * 100
		if w < 0.5 {
			return ""
		}
		return fmt.Sprintf(`<td style="background:%s;height:14px;width:%.1f%%"></td>`, color, w)
	}
	other := c.ExpCur - c.DynCur
	legend := func(color, label string, cur, base int64) string {
		return `<div style="font-size:13px;margin:3px 0"><span style="display:inline-block;width:10px;height:10px;background:` + color + `;margin-right:6px"></span>` +
			esc(label) + `: <b>` + n(cur) + `</b> <span style="color:` + cMuted + `">(` + esc(l.delta(float64(cur), float64(base))) + `)</span></div>`
	}
	return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-radius:4px;overflow:hidden"><tr>` +
		seg(c.DynCur, cOrange) + seg(other, cAmber) + seg(c.CheapCur, cGreen) + `</tr></table>` +
		legend(cOrange, l.t("built by the origin / Worker", "源站 / Worker 实时生成"), c.DynCur, c.DynBase) +
		legend(cAmber, l.t("other cache misses", "其他未命中缓存"), other, c.ExpBase-c.DynBase) +
		legend(cGreen, l.t("served from the edge cache", "缓存直接返回"), c.CheapCur, c.CheapBase)
}

// barTable lists rows with a proportional bar; tag marks new entries.
func barTable(rows [][3]string, values []int64) string {
	var top int64
	for _, v := range values {
		top = max(top, v)
	}
	if top <= 0 || len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px">`)
	for i, r := range rows {
		w := float64(values[i]) / float64(top) * 100
		b.WriteString(`<tr><td style="padding:4px 8px 4px 0;word-break:break-all;width:55%">` + r[0] + r[2] + `</td>` +
			`<td style="padding:4px 0;width:30%"><div style="background:` + cBlue + `;opacity:.75;height:10px;width:` + fmt.Sprintf("%.1f", max(w, 1)) + `%"></div></td>` +
			`<td style="padding:4px 0 4px 8px;text-align:right;white-space:nowrap">` + r[1] + `</td></tr>`)
	}
	b.WriteString(`</table>`)
	return b.String()
}

func (l lang) faceTable(cur, base []cfapi.Face, ua bool) string {
	old := map[string]bool{}
	for _, f := range base {
		old[f.Name] = true
	}
	var rows [][3]string
	var vals []int64
	for i, f := range cur {
		if i >= 6 {
			break
		}
		name := clip(f.Name, 70)
		if ua {
			name = l.friendlyUA(f.Name)
		}
		tag := ""
		if !old[f.Name] {
			tag = ` <span style="background:#fee2e2;color:` + cRed + `;border-radius:3px;padding:0 4px;font-size:11px">` + esc(l.t("new", "新")) + `</span>`
		}
		rows = append(rows, [3]string{esc(name), n(f.Count), tag})
		vals = append(vals, f.Count)
	}
	return barTable(rows, vals)
}

func (l lang) pathTable(ps []analyze.PathDelta) string {
	var rows [][3]string
	var vals []int64
	for _, p := range ps {
		rows = append(rows, [3]string{esc(clip(p.Path, 70)), n(p.Cur) + ` <span style="color:` + cMuted + `">(` + esc(l.delta(float64(p.Cur), float64(p.Base))) + `)</span>`, ""})
		vals = append(vals, p.Cur)
	}
	return barTable(rows, vals)
}

func pre(text string) string {
	return `<pre style="white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;background:#f9fafb;border:1px solid ` + cLine + `;border-radius:6px;padding:12px;margin:0">` + esc(text) + `</pre>`
}

// IntradayHTML renders an alert for email: accent by severity, headline,
// the key numbers, the charts, then the full text report.
func IntradayHTML(language string, d IntradayData, text string, cs []Chart) string {
	l := lang(language)
	accent := cRed
	switch {
	case d.Decision == state.DecRecovered:
		accent = cGreen
	case d.Severity.Level == analyze.SevLow:
		accent = cAmber
	}
	first, _, _ := strings.Cut(text, "\n")
	var b strings.Builder
	b.WriteString(`<div style="font-size:18px;font-weight:600">` + esc(first) + `</div>`)
	if d.Decision != state.DecRecovered {
		b.WriteString(`<div style="font-size:14px;margin-top:6px">` + esc(l.headline(d.Findings)) + `</div>`)
	}
	b.WriteString(`<div style="font-size:12px;color:` + cMuted + `;margin-top:4px">` + esc(l.window(d.Window, d.Loc)) + `</div>`)
	if d.Decision != state.DecRecovered {
		b.WriteString(h2(l.t("Compared with the same hour yesterday", "对比昨日同时段")))
		b.WriteString(l.tiles(d.Cur, d.Base))
	}
	if len(cs) > 0 {
		b.WriteString(h2(l.t("Last 24 hours", "过去 24 小时")))
		b.WriteString(charts(cs))
	}
	b.WriteString(h2(l.t("Full report", "完整报告")))
	b.WriteString(pre(text))
	return page(first, accent, b.String())
}

// DailyHTML renders the daily report for email.
func DailyHTML(language string, d DailyData, text string, cs []Chart) string {
	l := lang(language)
	accent := cGreen
	if len(d.Findings) > 0 {
		accent = cRed
	}
	lines := strings.SplitN(text, "\n", 3)
	var b strings.Builder
	b.WriteString(`<div style="font-size:18px;font-weight:600">` + esc(lines[0]) + `</div>`)
	if len(lines) > 1 {
		b.WriteString(`<div style="font-size:14px;margin-top:6px">` + esc(lines[1]) + `</div>`)
	}
	b.WriteString(`<div style="font-size:12px;color:` + cMuted + `;margin-top:4px">` + esc(l.window(d.Window, d.Loc)) + `</div>`)
	b.WriteString(h2(l.t("Last 24 hours vs the 24 before", "过去 24 小时对比前 24 小时")))
	b.WriteString(l.tiles(d.Cur, d.Base))
	if len(cs) > 0 {
		b.WriteString(charts(cs))
	}
	if d.Cost != nil {
		b.WriteString(h2(l.t("Where the traffic went", "流量去向")))
		b.WriteString(l.costBar(*d.Cost))
	}
	if t := l.pathTable(d.DynamicPaths); t != "" {
		b.WriteString(h2(l.t("Paths that reach the origin most", "回源最多的路径")))
		b.WriteString(t)
	}
	if t := l.faceTable(d.Cur.TopASN, d.Base.TopASN, false); t != "" {
		b.WriteString(h2(l.t("Main source networks", "主要来源网络")))
		b.WriteString(t)
	}
	if t := l.faceTable(d.Cur.TopUA, d.Base.TopUA, true); t != "" {
		b.WriteString(h2(l.t("Main clients", "主要访问者")))
		b.WriteString(t)
	}
	if d.Calibration != nil && !d.HideStatus {
		b.WriteString(`<div style="font-size:12px;color:` + cMuted + `;margin-top:14px">` + esc(l.calibrationLine(*d.Calibration)) + `</div>`)
	}
	b.WriteString(h2(l.t("Full report", "完整报告")))
	b.WriteString(pre(text))
	return page(lines[0], accent, b.String())
}
