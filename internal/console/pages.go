package console

import (
	"bytes"
	"context"
	"fmt"
	"github.com/playwjj/flarehound/internal/purpose"
	"html"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/ruleexec"
	"github.com/playwjj/flarehound/internal/sim"
	"github.com/playwjj/flarehound/internal/store"
	"github.com/playwjj/flarehound/internal/wafkit"
)

// page is the data every template receives.
type page struct {
	Title   string
	Req     *Req
	Lang    string
	Here    string // this page, for the language switch to come back to
	Zones   []config.Zone
	Zone    config.Zone
	Nav     string // active tab
	Refresh int    // seconds; 0: no auto-refresh
	Version string
	Msg     string
	Err     string
	Flash   string
	Next    string
	Action  string
	Token   string
	Role    string

	// views
	NoASN       bool // the plan's analytics have no ASN dimension
	Attention   []ZoneAttention
	Settings    *settingsView
	ASN         *ASNInfo
	CanSettings bool // admin of a console that manages settings
	CanSnap     bool // may create snapshots (console.snapshots)
	SChange     *settingsChange
	Diff        []string
	Replays     []Replay
	IsKnown     func(dim, name string) bool
	Overview    *Overview
	Live        *LiveView
	Drill       *Drill
	Chart       template.HTML
	Movers      *Movers
	Blocked     *Blocked
	IPs         *IPBoard
	Trend       template.HTML
	Dim         string
	Faces       *NewFaces
	Purpose     string // purpose filter of the UA lists ("" = all)
	Days        int
	History     *History
	Range       string
	Audit       *auditView
	Active      []store.BlockEvent
	Log         []store.BlockEvent

	// writes (v1.4)
	CanWrite bool // this viewer may block (admin, console holds the write token)
	WriteOn  bool // this console holds the write token
	// TOTPHint: an admin of a console holding the write token, with
	// console.require_totp off and the hint not dismissed.
	TOTPHint  bool
	LiveB     *liveBlocks
	Form      *blockForm
	Prep      *blockcli.Prepared
	Target    block.Target
	Reason    string
	Entries   []block.Entry
	Event     store.BlockEvent
	Until     int64
	UntilTime time.Time
	Effect    *Effect

	// rule simulator (v1.19)
	SimForm *simForm
	Sim     *sim.Report

	// WAF rules (v1.7)
	Rules     *rulesView
	CanRules  bool
	Backups   []store.RuleBackup
	Recipes   []wafkit.Recipe
	Recipe    *wafkit.Recipe
	Inputs    map[string]string
	RuleOp    *ruleOp
	Plan      *ruleexec.Plan
	Sentence  string
	Notes     []string
	RSVersion string // ruleset version the review was planned on
	Fixes     []wafkit.Fix
	Quota     map[string]rulesView // per Cloudflare phase
	ZonePlan  string

	// third-party sign-in
	Providers  []*Provider
	Identities []Identity
	UserIDs    map[int64][]Identity // users page: identities per account

	// snapshots
	Snapshot   bool         // rendering a self-contained snapshot
	CSS        template.CSS // inlined stylesheet (snapshots)
	SnapAt     time.Time
	SnapView   string // view key for the snapshot form
	SnapParams string // encoded view parameters
	Snapshots  []Snapshot
	ShareLink  string

	// accounts
	Sessions   []Session
	TOTPSecret string
	TOTPURI    string
	TOTPQR     template.HTML
	ResetOn    bool // password reset by e-mail is available
	Users      []User
	Invites    []Invite
	AuditLog   []AuditEntry
	Secret     string // one-time temporary password
	SecretFor  string
	InviteLink string
}

type auditView struct {
	At       time.Time
	Text     string
	Problems int
	NA       string
	Err      bool
	Refused  bool
	Fixes    []wafkit.Fix
}

// geoTag is the console's compact IP location: " (IN)" with the
// country's name as a tooltip.
func geoTag(ip string, l lang) template.HTML {
	code := geoip.Country(ip)
	if code == "" {
		return ""
	}
	return template.HTML(` <span class="geo" title="` + html.EscapeString(l.t("ip_location")+": "+geoip.Name(code, string(l))) + `">(` + html.EscapeString(code) + `)</span>`)
}

func urlQuery(s string) string { return url.QueryEscape(s) }

func (s *Server) funcs(l lang) template.FuncMap {
	return template.FuncMap{
		"t":    func(k string) string { return l.t(k) },
		"list": func(a ...any) []any { return a },
		"rowsCtx": func(p page, rows []Mover) []any {
			ctx := struct {
				Dim, ZoneName, Reason, CSRF, Here string
				Can, Snap, Known                  bool
			}{p.Dim, p.Zone.Name, "movers: " + p.Dim, p.Req.CSRF, p.Here, p.CanWrite && !p.Snapshot, p.Snapshot, p.CanSettings && !p.Snapshot}
			return []any{ctx, rows}
		},
		"blockValue": func(dim, name string) string {
			if dim == DimASN {
				return strings.TrimPrefix(strings.ToUpper(name), "AS")
			}
			return name
		},
		"unix": func(t time.Time) int64 { return t.Unix() },
		"now":  func() time.Time { return s.Now() },
		"sub":  func(a, b int64) int64 { return a - b },
		"tr": func(f [2]string) string {
			if l == "zh" {
				return f[1]
			}
			return f[0]
		},
		"phaseShort":    func(p string) string { return ruleexec.PhaseName(p) },
		"ruleSentence":  func(r map[string]any) string { return wafkit.RuleSentence(r, string(l)) },
		"thresholdRows": thresholdRows,
		"contains":      contains,
		"join":          func(s []string) string { return strings.Join(s, ", ") },
		"signal":        func(key string) string { return report.SignalTitle(string(l), key) },
		// intro is the one line under the tabs that says what question the
		// page answers; "" for pages without one.
		"intro": func(nav string) string {
			if _, ok := dict["intro_"+nav]; !ok {
				return ""
			}
			return l.t("intro_" + nav)
		},
		// evLabel / evDetail: an alert event names its signals in plain
		// words; other events (blocks, rule changes) are shown as recorded.
		"evLabel": func(e Event) string {
			if !alertEvent(e.Kind) {
				return e.Label
			}
			switch e.Label {
			case "changed", "escalate":
				return l.t("dec_" + e.Label)
			}
			return ""
		},
		"evDetail": func(e Event) string {
			if !alertEvent(e.Kind) || e.Detail == "" {
				return e.Detail
			}
			var ts []string
			for _, k := range strings.Split(e.Detail, ", ") {
				ts = append(ts, report.SignalTitle(string(l), k))
			}
			sep := ", "
			if l == "zh" {
				sep = "、"
			}
			return strings.Join(ts, sep)
		},
		"asnInfo":     func(name string) ASNInfo { return s.asnInfo(name) },
		"verdict":     func(e Effect) string { _, v := e.Verdict(string(l)); return v },
		"verdictKind": func(e Effect) string { k, _ := e.Verdict(string(l)); return k },
		"coverOf":     func(zone, dim, name string) *analyze.RuleCover { return s.coverOf(zone, dim, name) },
		"drillable":   func(dim, name string) bool { _, ok := drillFilter(dim, name); return ok },
		"purposeTag":  func(dim, name string) *PurposeTag { return s.purposeTag(l, dim, name) },
		"labelTag": func(lb *purpose.Label) *PurposeTag {
			if lb == nil {
				return nil
			}
			return purposeTagOf(l, *lb)
		},
		"className":      func(c string) string { return report.ClassName(string(l), purpose.Class(c)) },
		"purposeClasses": PurposeClasses,
		"choicesFor":     func(p wafkit.Param, plan string) []string { return p.ChoicesFor(plan) },
		"full": func(q map[string]rulesView, phase string) bool {
			v, ok := q[phase]
			return ok && v.Limit > 0 && v.Used >= v.Limit
		},
		"quotaOf": func(q map[string]rulesView, phase string) rulesView { return q[phase] },
		"providerLabel": func(name string) string {
			switch name {
			case "google":
				return "Google"
			case "github":
				return "GitHub"
			}
			return name
		},
		"formQuery": func(f *blockForm) template.URL { return template.URL(f.query()) },
		"fmtFace": func(fs []cfapi.Face) string {
			var parts []string
			for _, f := range fs {
				parts = append(parts, f.Name+": "+fmtNum(f.Count))
			}
			if len(parts) == 0 {
				return "—"
			}
			return strings.Join(parts, " · ")
		},
		// geo follows an address (or CIDR) with its IP location, "(IN)",
		// the country's name on hover; nothing without a library.
		"geo": func(ip string) template.HTML { return geoTag(ip, l) },
		// geoOf is geo for a block target: IP targets only.
		"geoOf": func(typ any, value string) template.HTML {
			if fmt.Sprint(typ) != "ip" {
				return ""
			}
			return geoTag(value, l)
		},
		"geoLabel":    func(code string) string { return geoip.Label(code, string(l)) },
		"tf":          func(k string, a ...any) string { return fmt.Sprintf(l.t(k), a...) },
		"simLabel":    func(c string) string { return sim.LabelText(c, string(l)) },
		"simVerdict":  func(r *sim.Report) string { return r.VerdictText(string(l)) },
		"simWarn":     func(r *sim.Report, w sim.Warn) string { return r.WarnText(w, string(l)) },
		"simReason":   func(it sim.Item) string { return sim.ReasonText(it, string(l)) },
		"simNetWhy":   func(why string) string { return sim.NetWhyText(why, string(l)) },
		"simPct":      sim.Pct,
		"simTermMark": sim.TermMark,
		"simTermText": func(st string) string { return sim.TermText(st, string(l)) },
		"simNum":      func(r *sim.Report, v int64) string { return r.Num(v, string(l)) },
		"simBound":    func(r *sim.Report, v int64) string { return r.Bound(v) },
		"simPerDay":   func(r *sim.Report) int64 { return int64(r.NetPerDay()) },
		"simLink":     simLink,
		"prediction":  func(e *Effect) string { return e.PredictionLine(string(l)) },
		"num":         fmtNum,
		"numf": func(v float64, unit string) string {
			if unit == "ms" {
				return fmt.Sprintf("%.1f ms", v)
			}
			return fmtNum(int64(math.Round(v)))
		},
		"pct": func(v float64) string {
			if math.Abs(v) >= 1000 {
				return fmt.Sprintf("%+.0f%%", v)
			}
			return fmt.Sprintf("%+.1f%%", v)
		},
		"delta": func(v int64) string {
			if v > 0 {
				return "+" + fmtNum(v)
			}
			return fmtNum(v)
		},
		"when": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(s.Cfg.Location).Format("2006-01-02 15:04")
		},
		"hm":     func(t time.Time) string { return t.In(s.Cfg.Location).Format("15:04") },
		"ago":    func(t time.Time) string { return fmtAgo(s.Now().Sub(t), string(l)) },
		"tz":     func() string { return s.Cfg.Location.String() },
		"zq":     func(z config.Zone) string { return url.QueryEscape(z.Name) },
		"locked": func(u User) bool { return s.Now().Before(u.LockedUntil) },
		"short": func(s string, n int) string {
			if len([]rune(s)) <= n {
				return s
			}
			return string([]rune(s)[:n-1]) + "…"
		},
		"roleName": func(r string) string { return l.t("role_" + r) },
		"evName":   func(k string) string { return l.t("ev_" + k) },
		"isNow":    func(sess Session, rq *Req) bool { return rq.Session != nil && sess.Hash == rq.Session.Hash },
	}
}

func fmtNum(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := fmt.Sprint(n)
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

func fmtAgo(d time.Duration, l string) string {
	zh := l == "zh"
	switch {
	case d < time.Minute:
		if zh {
			return "刚刚"
		}
		return "just now"
	case d < time.Hour:
		if zh {
			return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
		}
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		if zh {
			return fmt.Sprintf("%d 小时前", int(d.Hours()))
		}
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	if zh {
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Req = reqOf(r)
	p.WriteOn = s.CanWrite()
	p.CanWrite = p.WriteOn && p.Req.User != nil && p.Req.User.Admin()
	p.Lang = string(s.L(r))
	p.CanSettings = s.settingsOn() && p.Req.User != nil && p.Req.User.Admin()
	p.TOTPHint = p.CanWrite && s.totpHint()
	p.CanSnap = s.canSnapshot(p.Req)
	p.Here = "/"
	if r.Method == http.MethodGet {
		p.Here = r.URL.RequestURI()
	}
	p.Version = s.Version
	if p.Zones == nil {
		p.Zones = s.Cfg.Cloudflare.Zones
	}
	if p.Zone.ZoneID == "" && len(p.Zones) > 0 {
		p.Zone = p.Zones[0]
	}
	out, err := s.renderBytes(name, p)
	if err != nil {
		log.Printf("console: template %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func (s *Server) renderBytes(name string, p page) ([]byte, error) {
	if p.Lang != "en" && p.Lang != "zh" {
		p.Lang = string(s.defLang)
	}
	p.Version = s.Version
	if p.Zones == nil {
		p.Zones = s.Cfg.Cloudflare.Zones
	}
	if p.Req == nil {
		p.Req = &Req{Secure: true, Loopback: true}
	}
	var buf bytes.Buffer
	if err := s.tmpls[lang(p.Lang)].ExecuteTemplate(&buf, name, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zone picks the zone named by ?z= (name or ID), default the first.
func (s *Server) zone(r *http.Request) config.Zone {
	want := r.URL.Query().Get("z")
	if want == "" {
		want = r.PostFormValue("z")
	}
	for _, z := range s.Cfg.Cloudflare.Zones {
		if z.Name == want || z.ZoneID == want {
			return z
		}
	}
	return s.Cfg.Cloudflare.Zones[0]
}

// Views that can also be exported as snapshots are built from their
// query parameters alone.
const (
	viewOverview = "overview"
	viewMovers   = "movers"
	viewHistory  = "history"
	viewAudit    = "audit" // snapshots only (the page has its own handler)
	viewRules    = "rules" // snapshots only
)

func (s *Server) zoneOf(q url.Values) config.Zone {
	want := q.Get("z")
	for _, z := range s.Cfg.Cloudflare.Zones {
		if z.Name == want || z.ZoneID == want {
			return z
		}
	}
	return s.Cfg.Cloudflare.Zones[0]
}

// buildView builds one exportable view: template name and page data.
func (s *Server) buildView(ctx context.Context, view string, q url.Values) (string, page, error) {
	z := s.zoneOf(q)
	switch view {
	case viewOverview:
		ov, err := BuildOverview(s.Archive, s.eff(), z, s.Now())
		if err != nil {
			return "", page{}, err
		}
		p := page{Title: s.lc(ctx).t("nav_overview"), Zone: z, Nav: "overview", Overview: &ov, Refresh: s.Cfg.Console.RefreshSeconds,
			SnapView: view, SnapParams: url.Values{"z": {z.Name}}.Encode()}
		p.Live = s.liveView(ctx, z)
		if tr, ok := buildTrend(s.Archive, z, s.Now(), s.Cfg.Location, p.Live); ok {
			p.Trend = tr
		}
		if ov.Has {
			// Up to the end of the hour in progress, so a fresh block or
			// alert is on the chart (its traffic point is simply not there yet).
			to := s.Now().Truncate(time.Hour).Add(time.Hour)
			if h, err := BuildHistory(s.Archive, z, to.Add(-48*time.Hour), to, s.eff().Thresholds.BaselineMinSamples); err == nil {
				p.Chart = historyChart(h, s.Cfg.Location, 720, 200, false)
			} else {
				log.Printf("console: overview chart: %v", err)
			}
		}
		return "overview", p, nil
	case viewMovers:
		dim := q.Get("dim")
		switch dim {
		case DimUA, DimASN, DimPath:
		default:
			dim = DimUA
		}
		pf := ""
		if dim == DimUA {
			pf = purposeParam(q.Get("purpose"))
		}
		limit := 10
		if pf != "" {
			limit = 200 // filter the whole list, then keep ten
		}
		mv, err := BuildMovers(s.Archive, s.eff(), z, dim, limit)
		if err != nil {
			return "", page{}, err
		}
		if pf != "" {
			t := s.eff().PurposeTable()
			mv.Up, mv.Down = filterMovers(t, mv.Up, pf), filterMovers(t, mv.Down, pf)
			mv.Up, mv.Down = mv.Up[:min(len(mv.Up), 10)], mv.Down[:min(len(mv.Down), 10)]
		}
		sp := url.Values{"z": {z.Name}, "dim": {dim}}
		if pf != "" {
			sp.Set("purpose", pf)
		}
		p := page{Title: s.lc(ctx).t("nav_movers"), Zone: z, Nav: "movers", Movers: &mv, Dim: dim, NoASN: dim == DimASN && s.noASN(ctx, z),
			Purpose: pf, Refresh: s.Cfg.Console.RefreshSeconds, SnapView: view, SnapParams: sp.Encode()}
		if mv.Has && s.Analytics != nil {
			p.Blocked = s.blocked(ctx, z, mv.Window, !s.noASN(ctx, z))
		}
		return "movers", p, nil
	case viewHistory:
		rng := q.Get("range")
		span := 7 * 24 * time.Hour
		switch rng {
		case "24h":
			span = 24 * time.Hour
		case "30d":
			span = 30 * 24 * time.Hour
		default:
			rng = "7d"
		}
		end := s.Now().Truncate(time.Hour).Add(time.Hour) // include the hour in progress (events)
		endParam := ""
		if e := q.Get("end"); e != "" {
			if t, err := time.ParseInLocation("2006-01-02", e, s.Cfg.Location); err == nil {
				end, endParam = t.Add(24*time.Hour), e
			}
		}
		h, err := BuildHistory(s.Archive, z, end.Add(-span), end, s.eff().Thresholds.BaselineMinSamples)
		if err != nil {
			return "", page{}, err
		}
		params := url.Values{"z": {z.Name}, "range": {rng}}
		if endParam != "" {
			params.Set("end", endParam)
		}
		p := page{Title: s.lc(ctx).t("nav_history"), Zone: z, Nav: "history", History: &h, Range: rng, SnapView: view, SnapParams: params.Encode()}
		p.Chart = historyChart(h, s.Cfg.Location, 960, 280, true)
		return "history", p, nil
	case viewAudit:
		// The cached audit (no Cloudflare call when it is fresh).
		e, _ := s.cachedAudit(ctx, z, false)
		return "audit", page{Title: s.lc(ctx).t("nav_audit"), Zone: z, Nav: "audit", Audit: s.auditView(e, false, s.lc(ctx)),
			SnapView: view, SnapParams: url.Values{"z": {z.Name}}.Encode()}, nil
	case viewRules:
		ph, _ := phaseOf(q.Get("phase"))
		v := s.cachedRules(ctx, z, ph, false)
		return "rules", page{Title: s.lc(ctx).t("nav_rules"), Zone: z, Nav: "rules", Rules: &v,
			SnapView: view, SnapParams: url.Values{"z": {z.Name}, "phase": {ph}}.Encode()}, nil
	}
	return "", page{}, fmt.Errorf("unknown view %q", view)
}

func (s *Server) viewPage(view string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, p, err := s.buildView(r.Context(), view, r.URL.Query())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.render(w, r, http.StatusOK, name, p)
	}
}

func (s *Server) facesPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	days := 7
	switch r.URL.Query().Get("days") {
	case "1":
		days = 1
	case "30":
		days = 30
	}
	nf, err := BuildNewFaces(s.Archive, s.eff(), z, s.Now().Add(-time.Duration(days)*24*time.Hour), 50)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pf := purposeParam(r.URL.Query().Get("purpose"))
	nf.ByDim[DimUA] = filterFaces(s.eff().PurposeTable(), nf.ByDim[DimUA], pf)
	s.render(w, r, http.StatusOK, "faces", page{Title: s.L(r).t("nav_faces"), Zone: z, Nav: "faces", Faces: &nf, Days: days, NoASN: s.noASN(r.Context(), z), Purpose: pf,
		Refresh: s.Cfg.Console.RefreshSeconds})
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	e, _ := s.cachedAudit(r.Context(), z, false)
	s.render(w, r, http.StatusOK, "audit", page{Title: s.L(r).t("nav_audit"), Zone: z, Nav: "audit", Audit: s.auditView(e, false, s.L(r)), CanRules: s.canEditRules(r),
		SnapView: viewAudit, SnapParams: url.Values{"z": {z.Name}}.Encode()})
}

func (s *Server) auditRun(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	e, refused := s.cachedAudit(r.Context(), z, true)
	if !refused {
		s.audit(r, "waf_audit_run", z.Name, "")
	}
	s.render(w, r, http.StatusOK, "audit", page{Title: s.L(r).t("nav_audit"), Zone: z, Nav: "audit", Audit: s.auditView(e, refused, s.L(r)), CanRules: s.canEditRules(r)})
}

func (s *Server) auditView(e auditEntry, refused bool, l lang) *auditView {
	v := &auditView{At: e.at, Refused: refused}
	if e.err != nil {
		log.Printf("console: WAF audit: %v", e.err)
		v.Err = true
		return v
	}
	v.NA = e.data.NA
	if v.NA == "" {
		v.Problems = e.data.Result.Problems()
		v.Fixes = wafkit.Fixes(e.data.Result, string(l))
	}
	v.Text = report.Audit(string(l), e.data, "")
	return v
}

func (s *Server) blocksPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	active, err := s.Archive.ActiveBlocks(z.ZoneID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.Now()
	logs, err := s.Archive.BlockEventsBetween(z.ZoneID, now.Add(-30*24*time.Hour), now.Add(time.Minute), 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := page{Title: s.L(r).t("nav_blocks"), Zone: z, Nav: "blocks", Active: active, Log: logs, Flash: r.URL.Query().Get("ok")}
	if s.CanWrite() {
		ctx, cancel := context.WithTimeout(r.Context(), writeTO)
		defer cancel()
		lb := s.loadLive(ctx, z)
		p.LiveB = &lb
		if lb.Pending {
			p.Refresh = 15 // attempts arrive shortly
		}
	}
	s.render(w, r, http.StatusOK, "blocks", p)
}

// noASN reports a plan without the ASN analytics dimension (Free).
func (s *Server) noASN(ctx context.Context, z config.Zone) bool {
	if s.Caps == nil {
		return false
	}
	c := s.Caps(ctx, z)
	return c.Probed && !c.HasDim(cfapi.DimASN)
}

// alertEvent: the history event comes from an alert (its detail lists
// signal keys).
func alertEvent(kind string) bool { return kind == "alert" || kind == "held" || kind == "recovered" }
