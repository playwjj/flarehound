package console

// The cross-zone home (v1.10): with several zones, "/" lists them all,
// most in need of attention first — an open alert episode, origin 5xx
// over its line, other lines over, new faces, recent alerts — so a round
// of checks starts with one page instead of one zone at a time. Built
// from the archive and the watch's state files only: no Cloudflare query.

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/state"
)

// ZoneAttention is one zone's row on the home page.
type ZoneAttention struct {
	Zone      config.Zone
	Score     int
	NoData    bool
	Stale     bool
	Window    time.Time // end of the newest settled hour
	Open      bool      // an alert episode is open
	OpenSince time.Time
	OpenKeys  []string
	Origin5xx bool // origin 5xx over its line
	OriginOut bool // edge 52x over its line: the origin is not reachable
	OverLines int  // metrics over their line
	Watching  int  // metrics past half their line
	NewFaces  int  // first seen in the last 24 h, not known
	Alerts24h int
	Blocks    int
	TotalPct  float64
	HasBase   bool
}

func (s *Server) zoneAttention(z config.Zone) ZoneAttention {
	now := s.Now()
	a := ZoneAttention{Zone: z}
	eff := s.eff()
	if st, err := state.Load(check.StatePath(eff, z)); err == nil && st.Active {
		a.Open, a.OpenSince = true, st.FirstAlertAt
		for k := range st.Keys {
			a.OpenKeys = append(a.OpenKeys, k)
		}
		sort.Strings(a.OpenKeys)
	}
	ov, err := BuildOverview(s.Archive, eff, z, now)
	if err != nil || !ov.Has {
		a.NoData = true
	} else {
		a.Stale, a.Window, a.Alerts24h = ov.Stale, ov.Window.To, ov.AlertsToday
		for _, r := range ov.Rows {
			switch r.Status {
			case StatusAlert:
				a.OverLines++
				switch r.Key {
				case "m_origin5xx":
					a.Origin5xx = true
				case "m_unreachable":
					a.OriginOut = true
				}
			case StatusWatch:
				a.Watching++
			}
			if r.Key == "m_total" && r.HasBase {
				a.TotalPct, a.HasBase = r.Pct, true
			}
		}
	}
	if nf, err := BuildNewFaces(s.Archive, eff, z, now.Add(-24*time.Hour), 200); err == nil {
		for _, fs := range nf.ByDim {
			for _, f := range fs {
				if !f.Known {
					a.NewFaces++
				}
			}
		}
	}
	if bs, err := s.Archive.ActiveBlocks(z.ZoneID); err == nil {
		a.Blocks = len(bs)
	}
	// Most urgent first: an open episode, origin errors, any line over,
	// then the softer signals.
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	a.Score = 10000*b(a.Open) + 8000*b(a.OriginOut) + 5000*b(a.Origin5xx) + 1000*a.OverLines + 200*b(a.Stale || a.NoData) +
		50*a.Watching + 10*min(a.NewFaces, 50) + a.Alerts24h
	return a
}

func (s *Server) attentionPage(w http.ResponseWriter, r *http.Request) {
	var rows []ZoneAttention
	for _, z := range s.Cfg.Cloudflare.Zones {
		rows = append(rows, s.zoneAttention(z))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return strings.ToLower(rows[i].Zone.Name) < strings.ToLower(rows[j].Zone.Name)
	})
	s.render(w, r, http.StatusOK, "attention", page{Title: s.L(r).t("attention_title"), Attention: rows, Refresh: s.Cfg.Console.RefreshSeconds})
}
