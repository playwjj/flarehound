package console

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/store"
)

// page is the data every template receives.
type page struct {
	Title   string
	Req     *Req
	Lang    string
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
	Overview *Overview
	Chart    template.HTML
	Movers   *Movers
	Dim      string
	Faces    *NewFaces
	Days     int
	History  *History
	Range    string
	Audit    *auditView
	Active   []store.BlockEvent
	Log      []store.BlockEvent

	// accounts
	Sessions   []Session
	TOTPSecret string
	TOTPURI    string
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
}

func urlQuery(s string) string { return url.QueryEscape(s) }

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"t":    func(k string) string { return s.lang.t(k) },
		"list": func(a ...string) []string { return a },
		"tf":   func(k string, a ...any) string { return fmt.Sprintf(s.lang.t(k), a...) },
		"num":  fmtNum,
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
		"ago":    func(t time.Time) string { return fmtAgo(s.Now().Sub(t), string(s.lang)) },
		"tz":     func() string { return s.Cfg.Location.String() },
		"zq":     func(z config.Zone) string { return url.QueryEscape(z.Name) },
		"locked": func(u User) bool { return s.Now().Before(u.LockedUntil) },
		"short": func(s string, n int) string {
			if len([]rune(s)) <= n {
				return s
			}
			return string([]rune(s)[:n-1]) + "…"
		},
		"roleName": func(r string) string { return s.lang.t("role_" + r) },
		"evName":   func(k string) string { return s.lang.t("ev_" + k) },
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
	p.Lang = string(s.lang)
	p.Version = s.Version
	if p.Zones == nil {
		p.Zones = s.Cfg.Cloudflare.Zones
	}
	if p.Zone.ZoneID == "" && len(p.Zones) > 0 {
		p.Zone = p.Zones[0]
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, p); err != nil {
		log.Printf("console: template %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
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

func (s *Server) overviewPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	ov, err := BuildOverview(s.Archive, s.Cfg, z, s.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := page{Title: s.lang.t("nav_overview"), Zone: z, Nav: "overview", Overview: &ov, Refresh: s.Cfg.Console.RefreshSeconds}
	if ov.Has {
		// Up to the end of the hour in progress, so a fresh block or
		// alert is on the chart (its traffic point is simply not there yet).
		to := s.Now().Truncate(time.Hour).Add(time.Hour)
		if h, err := BuildHistory(s.Archive, z, to.Add(-48*time.Hour), to); err == nil {
			p.Chart = historyChart(h, s.Cfg.Location, 720, 200, false)
		} else {
			log.Printf("console: overview chart: %v", err)
		}
	}
	s.render(w, r, http.StatusOK, "overview", p)
}

func (s *Server) moversPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	dim := r.URL.Query().Get("dim")
	switch dim {
	case DimUA, DimASN, DimPath:
	default:
		dim = DimUA
	}
	mv, err := BuildMovers(s.Archive, s.Cfg, z, dim, 10)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "movers", page{Title: s.lang.t("nav_movers"), Zone: z, Nav: "movers", Movers: &mv, Dim: dim,
		Refresh: s.Cfg.Console.RefreshSeconds})
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
	nf, err := BuildNewFaces(s.Archive, s.Cfg, z, s.Now().Add(-time.Duration(days)*24*time.Hour), 50)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "faces", page{Title: s.lang.t("nav_faces"), Zone: z, Nav: "faces", Faces: &nf, Days: days,
		Refresh: s.Cfg.Console.RefreshSeconds})
}

func (s *Server) historyPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	rng := r.URL.Query().Get("range")
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
	if e := r.URL.Query().Get("end"); e != "" {
		if t, err := time.ParseInLocation("2006-01-02", e, s.Cfg.Location); err == nil {
			end = t.Add(24 * time.Hour)
		}
	}
	h, err := BuildHistory(s.Archive, z, end.Add(-span), end)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := page{Title: s.lang.t("nav_history"), Zone: z, Nav: "history", History: &h, Range: rng}
	p.Chart = historyChart(h, s.Cfg.Location, 960, 280, true)
	s.render(w, r, http.StatusOK, "history", p)
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	e, _ := s.cachedAudit(r.Context(), z, false)
	s.render(w, r, http.StatusOK, "audit", page{Title: s.lang.t("nav_audit"), Zone: z, Nav: "audit", Audit: s.auditView(e, false)})
}

func (s *Server) auditRun(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	e, refused := s.cachedAudit(r.Context(), z, true)
	if !refused {
		s.audit(r, "waf_audit_run", z.Name, "")
	}
	s.render(w, r, http.StatusOK, "audit", page{Title: s.lang.t("nav_audit"), Zone: z, Nav: "audit", Audit: s.auditView(e, refused)})
}

func (s *Server) auditView(e auditEntry, refused bool) *auditView {
	v := &auditView{At: e.at, Refused: refused}
	if e.err != nil {
		log.Printf("console: WAF audit: %v", e.err)
		v.Err = true
		return v
	}
	v.NA = e.data.NA
	if v.NA == "" {
		v.Problems = e.data.Result.Problems()
	}
	v.Text = report.Audit(string(s.lang), e.data, "")
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
	s.render(w, r, http.StatusOK, "blocks", page{Title: s.lang.t("nav_blocks"), Zone: z, Nav: "blocks", Active: active, Log: logs})
}
