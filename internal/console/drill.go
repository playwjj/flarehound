package console

// Drill-down (docs/web-console-revision.md §4.2): what one mover consists
// of — its paths, status codes, cache status, and the other dimension
// (ASNs of a user agent, user agents of an ASN) — in the movers' window
// against the same hour yesterday. The archive keeps only Top lists, so
// these are live queries (Cloudflare keeps ~31 days), cached for a while.

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

// Analytics is the read-token analytics the drill-down needs.
type Analytics interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
}

const (
	drillTTL      = 10 * time.Minute
	drillLimit    = 10
	drillParallel = 4 // concurrent queries per drill-down
	dimStatus     = "edgeResponseStatus"
)

// DrillRow is one part of the entry: now, yesterday, change.
type DrillRow struct {
	Name     string
	Cur      int64
	Prev     int64
	PrevKnow bool // in yesterday's list (else below its last place)
	Share    float64
}

// DrillSection is one breakdown.
type DrillSection struct {
	Key  string // i18n key of the heading
	Dim  string // movers dim of the rows ("ua", "asn", "path") when they can be drilled further, else ""
	Rows []DrillRow
	Err  string
}

// Drill is one mover broken down.
type Drill struct {
	Dim, Name          string
	From, To, PrevFrom time.Time
	Cur, Prev          int64
	Sections           []DrillSection
	Err                string
	At                 time.Time
}

type drillEntry struct {
	mu sync.Mutex
	d  *Drill
}

// drillFilter selects the entry's requests.
func drillFilter(dim, name string) (cfapi.Filter, bool) {
	switch dim {
	case DimUA:
		return cfapi.Filter{UserAgent: name}, name != ""
	case DimASN:
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(name), "AS"))
		return cfapi.Filter{ASN: n}, err == nil && n > 0
	case DimPath:
		// Movers' paths are uncached requests (the expensive part).
		ok := strings.HasPrefix(name, "/") && !strings.ContainsAny(name, "%")
		return cfapi.Filter{PathLike: name, CacheStatus: "dynamic"}, ok
	}
	return cfapi.Filter{}, false
}

type breakdown struct {
	key, cfDim, dim string
}

func breakdownsFor(dim string) []breakdown {
	paths := breakdown{"drill_paths", cfapi.DimPath, DimPath}
	status := breakdown{"drill_status", dimStatus, ""}
	cache := breakdown{"drill_cache", cfapi.DimCacheStatus, ""}
	uas := breakdown{"drill_uas", cfapi.DimUserAgent, DimUA}
	asns := breakdown{"drill_asns", cfapi.DimASN, DimASN}
	switch dim {
	case DimUA:
		return []breakdown{paths, status, cache, asns}
	case DimASN:
		return []breakdown{paths, status, cache, uas}
	}
	return []breakdown{status, uas, asns} // path: already uncached
}

// buildDrill queries the breakdowns of one entry for [from, to) and the
// same window a day earlier.
func buildDrill(ctx context.Context, an Analytics, zone config.Zone, dim, name string, from, to time.Time) *Drill {
	d := &Drill{Dim: dim, Name: name, From: from, To: to, PrevFrom: from.Add(-24 * time.Hour)}
	f, ok := drillFilter(dim, name)
	if !ok {
		d.Err = "this entry cannot be selected in analytics"
		return d
	}
	z, pf, pt := zone.ZoneID, from.Add(-24*time.Hour), to.Add(-24*time.Hour)
	// The queries are independent: run them a few at a time. On a slow
	// link ten sequential round trips are the difference between a page
	// that opens and one people give up on.
	sem := make(chan struct{}, drillParallel)
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			f()
		}()
	}
	var curErr error
	run(func() { d.Cur, curErr = an.Count(ctx, z, from, to, f) })
	run(func() { d.Prev, _ = an.Count(ctx, z, pf, pt, f) })
	bds := breakdownsFor(dim)
	curs := make([][]cfapi.Face, len(bds))
	prevs := make([][]cfapi.Face, len(bds))
	errs := make([]error, len(bds))
	for i, b := range bds {
		i, b := i, b
		run(func() { curs[i], errs[i] = an.Top(ctx, z, from, to, b.cfDim, drillLimit, f) })
		run(func() { prevs[i], _ = an.Top(ctx, z, pf, pt, b.cfDim, 25, f) })
	}
	wg.Wait()
	if curErr != nil {
		d.Err = curErr.Error()
		return d
	}
	for i, b := range bds {
		sec := DrillSection{Key: b.key, Dim: b.dim}
		if errs[i] != nil {
			sec.Err = errs[i].Error()
			d.Sections = append(d.Sections, sec)
			continue
		}
		pm := map[string]int64{}
		for _, x := range prevs[i] {
			pm[x.Name] += x.Count
		}
		for _, x := range curs[i] {
			p, known := pm[x.Name]
			r := DrillRow{Name: x.Name, Cur: x.Count, Prev: p, PrevKnow: known}
			if d.Cur > 0 {
				r.Share = float64(x.Count) / float64(d.Cur) * 100
			}
			sec.Rows = append(sec.Rows, r)
		}
		sort.SliceStable(sec.Rows, func(i, j int) bool { return sec.Rows[i].Cur > sec.Rows[j].Cur })
		d.Sections = append(d.Sections, sec)
	}
	return d
}

// drill returns a cached breakdown (concurrent viewers share one query).
func (s *Server) drill(ctx context.Context, z config.Zone, dim, name string, from, to time.Time) *Drill {
	key := z.ZoneID + "|" + dim + "|" + name + "|" + strconv.FormatInt(from.Unix(), 10)
	s.drillMu.Lock()
	e := s.drillCache[key]
	if e == nil {
		if len(s.drillCache) > 500 { // bounded: drop everything stale
			for k, v := range s.drillCache {
				if v.d != nil && s.Now().Sub(v.d.At) > drillTTL {
					delete(s.drillCache, k)
				}
			}
		}
		e = &drillEntry{}
		s.drillCache[key] = e
	}
	s.drillMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.d != nil && s.Now().Sub(e.d.At) < drillTTL && e.d.Err == "" {
		return e.d
	}
	qctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	d := buildDrill(qctx, s.Analytics, z, dim, name, from, to)
	d.At = s.Now()
	e.d = d
	return d
}

func (s *Server) drillPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	q := r.URL.Query()
	dim, name := q.Get("dim"), q.Get("name")
	if _, ok := drillFilter(dim, name); !ok || len(name) > 500 {
		http.NotFound(w, r)
		return
	}
	p := page{Title: s.L(r).t("drill_title"), Zone: z, Nav: "movers", Dim: dim}
	if s.Analytics == nil {
		p.Err = s.L(r).t("drill_off")
		s.render(w, r, http.StatusOK, "drill", p)
		return
	}
	// The movers' window: the newest settled hour.
	win, ok, err := s.Archive.LatestHour(z.ZoneID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		p.Err = s.L(r).t("no_data")
		s.render(w, r, http.StatusOK, "drill", p)
		return
	}
	p.Drill = s.drill(r.Context(), z, dim, name, win.From, win.To)
	s.render(w, r, http.StatusOK, "drill", p)
}
