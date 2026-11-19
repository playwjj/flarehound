package console

// The console's read model: everything here is computed from the local
// archive the watch process writes, with the same calibration and the
// same baseline (28-day same-hour median) the alerts use — the console
// and the notifications never disagree on a number.

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

// Archive is the subset of the store the console reads.
type Archive interface {
	LatestHour(zone string) (store.Window, bool, error)
	HourAt(zone string, from time.Time) (store.Window, bool, error)
	SameHourSnapshots(zone string, from, to time.Time, days int) ([]store.Snapshot, error)
	HourSeries(zone string, from, to time.Time) ([]store.HourPoint, error)
	HourSnapshots(zone string, from, to time.Time) ([]store.HourSnapshot, error)
	FacesSince(zone, dim string, since time.Time, limit int) ([]store.FaceRecord, error)
	OldestFace(zone, dim string) (time.Time, error)
	AlertsDetailed(zone string, from, to time.Time, limit int) ([]store.AlertRecord, error)
	BlockEventsBetween(zone string, from, to time.Time, limit int) ([]store.BlockEvent, error)
	ActiveBlocks(zone string) ([]store.BlockEvent, error)
	RuleChanges(zone string, limit int) ([]store.RuleChange, error)
	ASNNames() (map[int]string, error)
}

// Status of one metric against its alert line.
const (
	StatusOK    = "ok"
	StatusWatch = "watch" // past half of the alert line
	StatusAlert = "alert" // past the alert line
	StatusNA    = "na"    // no baseline
	StatusBook  = "book"  // edge 52x that are bookkeeping (analyze.JudgeUnreachable): neutral
	// StatusWarming: the line's archive baseline is still accumulating
	// (a metric added days ago): no verdict either way, never "needs attention".
	StatusWarming = "warming"
)

// MetricRow is one line of the overview.
type MetricRow struct {
	Key      string // i18n key
	Subject  string // worker name, or ""
	Cur      float64
	Base     float64
	HasBase  bool
	Pct      float64 // (cur-base)/base*100
	Unit     string  // "" or "ms"
	Status   string
	LineDesc string // the alert line, e.g. "+35%"
	// Samples/Need: measured same-hour samples behind the baseline, and
	// how many it needs (StatusWarming).
	Samples, Need int
}

// Overview is the home page of one zone.
type Overview struct {
	Window      store.Window
	Has         bool
	Stale       bool // the newest archived hour is older than the watch cadence allows
	Samples     int  // same-hour baseline samples found (of analyze.LongBaselineDays)
	BaselineOK  bool // Samples >= analyze.LongBaselineMinSamples
	Rows        []MetricRow
	AlertsToday int
}

func pct(cur, base float64) float64 {
	if base == 0 {
		return 0
	}
	return (cur - base) / base * 100
}

func upStatus(cur, base, line float64, minCount int64, hasBase bool) string {
	if !hasBase || base <= 0 {
		return StatusNA
	}
	p := pct(cur, base)
	switch {
	case p >= line && cur >= float64(minCount):
		return StatusAlert
	case p >= line/2:
		return StatusWatch
	}
	return StatusOK
}

// staleAfter is how old the newest archived hour may be before the
// console says so: one watch interval, plus the offset, plus slack.
func staleAfter(cfg *config.Config) time.Duration {
	return cfg.IntradayInterval() + cfg.IntradayOffset() + 30*time.Minute
}

// metricRows compares cur with base line by line, each against its alert
// line from the config (the same lines the watch uses).
func metricRows(cfg *config.Config, zone config.Zone, cur, base analyze.Metrics, has bool) []MetricRow {
	var rows []MetricRow
	th := cfg.Thresholds
	add := func(r MetricRow) {
		r.HasBase = has
		if has {
			r.Pct = pct(r.Cur, r.Base)
		}
		rows = append(rows, r)
	}
	add(MetricRow{Key: "m_total", Cur: float64(cur.Total), Base: float64(base.Total),
		Status: upStatus(float64(cur.Total), float64(base.Total), th.TotalUpPct, th.MinCount, has), LineDesc: plusPct(th.TotalUpPct)})
	for _, wk := range zone.Workers {
		c, b := cur.Worker(wk), base.Worker(wk)
		add(MetricRow{Key: "m_worker_calls", Subject: wk, Cur: float64(c.Calls), Base: float64(b.Calls),
			Status: upStatus(float64(c.Calls), float64(b.Calls), th.WorkerCallsUpPct, th.MinCount, has), LineDesc: plusPct(th.WorkerCallsUpPct)})
		add(MetricRow{Key: "m_worker_cpu", Subject: wk, Cur: c.CPUP50ms, Base: b.CPUP50ms, Unit: "ms",
			Status: upStatus(c.CPUP50ms, b.CPUP50ms, th.CPUP50UpPct, 0, has && b.CPUP50ms > 0), LineDesc: plusPct(th.CPUP50UpPct)})
	}
	add(MetricRow{Key: "m_dynamic", Cur: float64(cur.Dynamic), Base: float64(base.Dynamic),
		Status: upStatus(float64(cur.Dynamic), float64(base.Dynamic), th.DynamicUpPct, th.MinCount, has), LineDesc: plusPct(th.DynamicUpPct)})

	o5 := MetricRow{Key: "m_origin5xx", Cur: float64(cur.Origin5xx), Base: float64(base.Origin5xx),
		LineDesc: "×" + strconv.FormatFloat(th.Origin5xxMultiple, 'f', -1, 64) + " & ≥" + strconv.FormatInt(th.Origin5xxMin, 10)}
	switch {
	case !has:
		o5.Status = StatusNA
	case cur.Origin5xx >= th.Origin5xxMin && float64(cur.Origin5xx) >= th.Origin5xxMultiple*math.Max(float64(base.Origin5xx), 1):
		o5.Status = StatusAlert
	case cur.Origin5xx >= th.Origin5xxMin/2 && float64(cur.Origin5xx) >= th.Origin5xxMultiple/2*math.Max(float64(base.Origin5xx), 1):
		o5.Status = StatusWatch
	default:
		o5.Status = StatusOK
	}
	if r, ok := cur.Origin5xxRate(); ok && cur.Origin5xx > 0 {
		o5.Subject = analyze.RatePct(r)
	}
	add(o5)
	rows = append(rows, originRows(th, cur, base, has)...)
	return rows
}

// originRows are the origin's own lines: reachability and latency. They
// fold away where the origin barely works — a zone served from the edge
// or a Worker has no origin worth a tile (FlareHound's "missing →
// degrade, never clutter").
func originRows(th config.Thresholds, cur, base analyze.Metrics, has bool) []MetricRow {
	co, bo := cur.Origin, base.Origin
	shown := co != nil && co.Requests >= analyze.OriginMinRequests
	var rows []MetricRow
	if shown || cur.Unreachable > 0 {
		u := MetricRow{Key: "m_unreachable", Cur: float64(cur.Unreachable), Base: float64(base.Unreachable), HasBase: has,
			LineDesc: "≥" + strconv.FormatInt(th.UnreachableMin, 10)}
		if has {
			u.Pct = pct(u.Cur, u.Base)
		}
		// The same judgement as the alert line and the reports.
		fire, c := analyze.UnreachableFires(cur, base, th.UnreachableMin)
		switch {
		case has && warming(&u, base, analyze.MetricUnreachable, th.BaselineMinSamples):
			// Too few measured hours behind the baseline: no verdict.
		case has && fire:
			u.Status = StatusAlert
		case has && c.Verdict == analyze.UnreachBook:
			// A steady 522/524 background with the origin answering:
			// bookkeeping (Worker zones) — neutral, never "needs attention".
			u.Status, u.Key = StatusBook, "m_unreachable_book"
			u.LineDesc = "×3"
		case cur.Unreachable > 0:
			u.Status = StatusWatch
		default:
			u.Status = StatusOK
		}
		rows = append(rows, u)
	}
	if !shown {
		return rows
	}
	hasBase := has && bo != nil && bo.Requests >= analyze.OriginMinRequests
	line := plusPct(th.OriginSlowUpPct) + " & ≥" + strconv.FormatFloat(th.OriginSlowMinMs, 'f', -1, 64) + " ms"
	lat := func(key string, c, b float64) MetricRow {
		r := MetricRow{Key: key, Cur: c, Unit: "ms", HasBase: hasBase && b > 0, LineDesc: line, Status: StatusNA}
		if r.HasBase && warming(&r, base, analyze.MetricOrigin, th.BaselineMinSamples) {
			r.Base, r.Pct = b, pct(c, b)
		} else if r.HasBase {
			r.Base, r.Pct = b, pct(c, b)
			switch {
			case r.Pct >= th.OriginSlowUpPct && c >= th.OriginSlowMinMs:
				r.Status = StatusAlert
			case r.Pct >= th.OriginSlowUpPct/2 && c >= th.OriginSlowMinMs/2:
				r.Status = StatusWatch
			default:
				r.Status = StatusOK
			}
		}
		return r
	}
	var bt, bf float64
	if bo != nil {
		bt, bf = bo.TTFBP95ms, bo.TotalP95ms
	}
	ttfb := lat("m_origin_ttfb", co.TTFBP95ms, bt)
	// Connection set-up rides along as detail, not its own alert line
	// (mostly 0: connections are reused).
	if co.TCPP95ms > 0 || co.TLSP95ms > 0 {
		ttfb.Subject = "TCP " + strconv.FormatFloat(co.TCPP95ms, 'f', 0, 64) + " · TLS " + strconv.FormatFloat(co.TLSP95ms, 'f', 0, 64) + " ms"
	}
	return append(rows, ttfb, lat("m_origin_total", co.TotalP95ms, bf))
}

// warming marks a row whose archive baseline is still accumulating for
// metric (fewer than min measured same-hour samples): neutral, with the
// count so far. A baseline that is not from the archive (Samples nil) is
// never warming.
func warming(r *MetricRow, base analyze.Metrics, metric string, min int) bool {
	if base.Samples == nil || min <= 0 {
		return false
	}
	n := base.Samples.Of(metric, r.Subject)
	if n >= min {
		return false
	}
	r.Status, r.Samples, r.Need = StatusWarming, n, min
	return true
}

// heldAlert reports whether an archived alert rested only on lines whose
// baseline was still accumulating when it was sent (alerts from before
// baseline maturity existed — v1.16.1 and older): read today, the watch
// would have held it, so it is not part of the anomaly history.
func heldAlert(a Archive, zone config.Zone, x store.AlertRecord, min int) bool {
	if min <= 0 || len(x.Findings) == 0 {
		return false
	}
	for _, f := range x.Findings {
		if analyze.RuleMetric(f.Rule) == "" {
			return false
		}
	}
	from := x.WindowTo.Add(-time.Hour)
	ss, err := a.SameHourSnapshots(zone.ZoneID, from, x.WindowTo, analyze.LongBaselineDays)
	if err != nil {
		return false
	}
	ms := make([]analyze.Metrics, 0, len(ss))
	for _, s := range ss {
		ms = append(ms, s.Metrics)
	}
	_, held := analyze.HoldImmature(x.Findings, analyze.CountSamples(ms), min)
	return len(held) == len(x.Findings)
}

// BuildOverview computes the overview from the newest archived hour.
func BuildOverview(a Archive, cfg *config.Config, zone config.Zone, now time.Time) (Overview, error) {
	var ov Overview
	w, ok, err := a.LatestHour(zone.ZoneID)
	if err != nil || !ok {
		return ov, err
	}
	ov.Window, ov.Has = w, true
	ov.Stale = now.Sub(w.To) > staleAfter(cfg)
	samples, err := a.SameHourSnapshots(zone.ZoneID, w.From, w.To, analyze.LongBaselineDays)
	if err != nil {
		return ov, err
	}
	ov.Samples = len(samples)
	ov.BaselineOK = ov.Samples >= analyze.LongBaselineMinSamples
	var ms []analyze.Metrics
	for _, s := range samples {
		ms = append(ms, s.Metrics)
	}
	ov.Rows = metricRows(cfg, zone, w.Metrics, analyze.Median(ms), len(ms) > 0)

	day := w.To.Add(-24 * time.Hour)
	if as, err := a.AlertsDetailed(zone.ZoneID, day, w.To.Add(time.Second), 100); err == nil {
		for _, x := range as {
			if x.Decision != "recovered" && !heldAlert(a, zone, x, cfg.Thresholds.BaselineMinSamples) {
				ov.AlertsToday++
			}
		}
	}
	return ov, nil
}

func plusPct(v float64) string { return "+" + strconv.FormatFloat(v, 'f', -1, 64) + "%" }

// --- movers ---

// Dims of the movers and new-faces views.
const (
	DimUA   = "ua"
	DimASN  = "asn"
	DimPath = "path"
	DimIP   = "ip" // IP board and drill-down only (not a movers list)
)

// Mover is one entry of a gainers / losers list. The archive keeps only
// each window's Top N, so an entry absent from a list is "below the last
// listed count", not zero: such values are upper bounds (Capped) and the
// change is reported conservatively.
type Mover struct {
	Name       string
	Cur        int64
	CurCapped  bool // not in the current Top N: Cur is an upper bound
	Base       int64
	BaseCapped bool // absent from most baseline samples: Base is an upper bound
	Delta      int64
	Pct        float64
	HasPct     bool
	Known      bool
}

// Movers is one dimension's gainers and losers for the newest hour.
type Movers struct {
	Window  store.Window
	Has     bool
	Samples int
	Up      []Mover
	Down    []Mover
	TopN    int // list length in the current window
}

func listOf(s store.Snapshot, dim string) []cfapi.Face {
	switch dim {
	case DimUA:
		return s.TopUA
	case DimASN:
		return s.TopASN
	case DimPath:
		return s.DynamicPaths
	}
	return nil
}

func floorOf(list []cfapi.Face) int64 {
	if len(list) == 0 {
		return 0
	}
	min := list[0].Count
	for _, f := range list {
		if f.Count < min {
			min = f.Count
		}
	}
	return min
}

func medianOf(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// IsKnown reports whether a face is in the user's known_faces library.
func IsKnown(cfg *config.Config, dim, name string) bool {
	switch dim {
	case DimASN:
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(name), "AS"))
		if err != nil {
			return false
		}
		for _, a := range cfg.KnownFaces.ASNs {
			if a == n {
				return true
			}
		}
	case DimUA:
		l := strings.ToLower(name)
		for _, s := range cfg.KnownFaces.UserAgents {
			if s != "" && strings.Contains(l, strings.ToLower(s)) {
				return true
			}
		}
	}
	return false
}

// BuildMovers ranks one dimension's entries by absolute change against
// the 28-day same-hour median (absolute, not percent: a 10 → 40 jump is
// noise next to 20 000 → 35 000).
func BuildMovers(a Archive, cfg *config.Config, zone config.Zone, dim string, limit int) (Movers, error) {
	var mv Movers
	w, ok, err := a.LatestHour(zone.ZoneID)
	if err != nil || !ok {
		return mv, err
	}
	mv.Window, mv.Has = w, true
	samples, err := a.SameHourSnapshots(zone.ZoneID, w.From, w.To, analyze.LongBaselineDays)
	if err != nil {
		return mv, err
	}
	var withList []store.Snapshot
	for _, s := range samples {
		if len(listOf(s, dim)) > 0 {
			withList = append(withList, s)
		}
	}
	mv.Samples = len(withList)
	curList := listOf(w.Snapshot, dim)
	mv.TopN = len(curList)
	curFloor := floorOf(curList)

	cur := map[string]int64{}
	names := map[string]bool{}
	for _, f := range curList {
		cur[f.Name] += f.Count
		names[f.Name] = true
	}
	for _, s := range withList {
		for _, f := range listOf(s, dim) {
			names[f.Name] = true
		}
	}
	if len(names) == 0 {
		return mv, nil
	}

	var all []Mover
	for name := range names {
		m := Mover{Name: name, Known: IsKnown(cfg, dim, name)}
		if c, ok := cur[name]; ok {
			m.Cur = c
		} else {
			m.Cur, m.CurCapped = curFloor, true
		}
		var present, caps []int64
		for _, s := range withList {
			found := false
			for _, f := range listOf(s, dim) {
				if f.Name == name {
					present = append(present, f.Count)
					found = true
					break
				}
			}
			if !found {
				caps = append(caps, floorOf(listOf(s, dim)))
			}
		}
		switch {
		case len(withList) == 0:
			m.Base, m.BaseCapped = 0, true
		case len(present)*2 > len(withList):
			// Mostly listed: missing samples count at their list floor
			// (an upper bound), which keeps the median conservative.
			m.Base = medianOf(append(present, caps...))
		default:
			// Mostly unlisted: the honest statement is "below ~X".
			m.Base, m.BaseCapped = medianOf(append(present, caps...)), true
		}
		m.Delta = m.Cur - m.Base
		if m.Base > 0 && !m.BaseCapped && !m.CurCapped {
			m.Pct, m.HasPct = pct(float64(m.Cur), float64(m.Base)), true
		}
		all = append(all, m)
	}

	for _, m := range all {
		// A riser must be in the current list; a faller must have a real
		// baseline. Comparing two upper bounds says nothing.
		if m.Delta > 0 && !m.CurCapped {
			mv.Up = append(mv.Up, m)
		}
		if m.Delta < 0 && !m.BaseCapped {
			mv.Down = append(mv.Down, m)
		}
	}
	sort.Slice(mv.Up, func(i, j int) bool { return mv.Up[i].Delta > mv.Up[j].Delta })
	sort.Slice(mv.Down, func(i, j int) bool { return mv.Down[i].Delta < mv.Down[j].Delta })
	if len(mv.Up) > limit {
		mv.Up = mv.Up[:limit]
	}
	if len(mv.Down) > limit {
		mv.Down = mv.Down[:limit]
	}
	return mv, nil
}

// --- new faces ---

// NewFace is a UA / ASN / path first seen recently.
type NewFace struct {
	Dim       string
	Name      string
	FirstSeen time.Time
	LastSeen  time.Time
	MaxCount  int64
	Cur       int64 // in the newest hour's Top list; 0 if absent
	InCur     bool
	Known     bool
}

// NewFaces groups recent faces per dimension.
type NewFaces struct {
	Since     time.Time
	Window    store.Window
	Has       bool
	ByDim     map[string][]NewFace
	PathSince time.Time // path faces are recorded since v1.3
}

// FaceSection is one dimension's list, in display order.
type FaceSection struct {
	Dim   string
	Faces []NewFace
}

// Sections returns the dims in display order.
func (nf NewFaces) Sections() []FaceSection {
	var out []FaceSection
	for _, d := range []string{DimUA, DimASN, DimPath} {
		out = append(out, FaceSection{Dim: d, Faces: nf.ByDim[d]})
	}
	return out
}

// BuildNewFaces lists faces first seen since `since`.
func BuildNewFaces(a Archive, cfg *config.Config, zone config.Zone, since time.Time, limit int) (NewFaces, error) {
	nf := NewFaces{Since: since, ByDim: map[string][]NewFace{}}
	w, ok, err := a.LatestHour(zone.ZoneID)
	if err != nil {
		return nf, err
	}
	nf.Window, nf.Has = w, ok
	for _, dim := range []string{DimUA, DimASN, DimPath} {
		recs, err := a.FacesSince(zone.ZoneID, dim, since, limit)
		if err != nil {
			return nf, err
		}
		cur := map[string]int64{}
		if ok {
			for _, f := range listOf(w.Snapshot, dim) {
				cur[f.Name] += f.Count
			}
		}
		for _, r := range recs {
			c, in := cur[r.Name]
			nf.ByDim[dim] = append(nf.ByDim[dim], NewFace{Dim: dim, Name: r.Name, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
				MaxCount: r.MaxCount, Cur: c, InCur: in, Known: IsKnown(cfg, dim, r.Name)})
		}
	}
	nf.PathSince, _ = a.OldestFace(zone.ZoneID, DimPath)
	return nf, nil
}

// --- history ---

// HistPoint is one hour of the history chart.
type HistPoint struct {
	From             time.Time
	Total, Dynamic   int64
	Has              bool
	Median, P25, P75 float64 // same-hour baseline of Total over the preceding 28 days
	HasBase          bool
}

// Event is a timeline marker.
type Event struct {
	At     time.Time
	Kind   string // alert | recovered | block | unblock | expire | rule
	Label  string
	Detail string
}

// History is a range of hours with baseline band and events.
type History struct {
	From, To time.Time
	Points   []HistPoint
	Events   []Event
}

func quantile(sorted []int64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return float64(sorted[lo])
	}
	f := pos - float64(lo)
	return float64(sorted[lo])*(1-f) + float64(sorted[hi])*f
}

// BuildHistory loads [from, to) hourly, with each hour's same-hour
// baseline from the 28 days before it, and the timeline events.
// minSamples is thresholds.baseline_min_samples: alerts sent while their
// baseline was still accumulating are shown as such (heldAlert).
func BuildHistory(a Archive, zone config.Zone, from, to time.Time, minSamples int) (History, error) {
	h := History{From: from, To: to}
	series, err := a.HourSeries(zone.ZoneID, from.Add(-time.Duration(analyze.LongBaselineDays)*24*time.Hour), to)
	if err != nil {
		return h, err
	}
	byTS := map[int64]store.HourPoint{}
	for _, p := range series {
		byTS[p.From.Unix()] = p
	}
	for t := from.Truncate(time.Hour); t.Before(to); t = t.Add(time.Hour) {
		hp := HistPoint{From: t}
		if p, ok := byTS[t.Unix()]; ok {
			hp.Total, hp.Dynamic, hp.Has = p.Total, p.Dynamic, true
		}
		var vals []int64
		for k := 1; k <= analyze.LongBaselineDays; k++ {
			if p, ok := byTS[t.Add(-time.Duration(k)*24*time.Hour).Unix()]; ok {
				vals = append(vals, p.Total)
			}
		}
		if len(vals) >= 7 {
			sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
			hp.Median, hp.P25, hp.P75, hp.HasBase = quantile(vals, 0.5), quantile(vals, 0.25), quantile(vals, 0.75), true
		}
		h.Points = append(h.Points, hp)
	}

	if as, err := a.AlertsDetailed(zone.ZoneID, from, to.Add(time.Hour), 500); err == nil {
		for _, x := range as {
			kind, label := "alert", x.Decision
			switch {
			case x.Decision == "recovered":
				kind = "recovered"
			case heldAlert(a, zone, x, minSamples):
				kind = "held" // sent before the fix, on a baseline still accumulating: not an anomaly
			}
			var rules []string
			for _, f := range x.Findings {
				rules = append(rules, f.Key())
			}
			h.Events = append(h.Events, Event{At: x.WindowTo, Kind: kind, Label: label, Detail: strings.Join(rules, ", ")})
		}
	} else {
		return h, err
	}
	if bs, err := a.BlockEventsBetween(zone.ZoneID, from, to, 500); err == nil {
		for _, b := range bs {
			h.Events = append(h.Events, Event{At: b.At, Kind: b.Op, Label: b.Op + " " + b.Type + " " + b.Value,
				Detail: strings.TrimSpace(b.Action + " " + b.Reason + " (" + b.Actor + ")")})
		}
	} else {
		return h, err
	}
	if rc, err := a.RuleChanges(zone.ZoneID, 500); err == nil {
		for _, c := range rc {
			if c.At.Before(from) || !c.At.Before(to) {
				continue
			}
			h.Events = append(h.Events, Event{At: c.At, Kind: "rule", Label: c.Op + " " + c.Phase, Detail: c.Detail + " (" + c.Actor + ")"})
		}
	} else {
		return h, err
	}
	sort.SliceStable(h.Events, func(i, j int) bool { return h.Events[i].At.After(h.Events[j].At) })
	return h, nil
}
