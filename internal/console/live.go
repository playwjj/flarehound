package console

// The live view (docs/web-console-revision.md §4.1 / §6): the last 60
// minutes, queried from Cloudflare on demand with the watch's own queries
// (check.Runner.Measure), against the 28-day baseline. A rolling hour
// straddles two clock hours, so the baseline blends their same-hour
// medians by how much of the window falls in each. The newest minutes
// are left out (analytics ingestion lag) and the result is marked
// unsettled: it may still grow by a few percent.

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/config"
)

// LiveMetrics measures any window with the watch's queries.
type LiveMetrics func(ctx context.Context, zone config.Zone, from, to time.Time) (analyze.Metrics, error)

const (
	liveLag    = 5 * time.Minute // analytics ingestion lag left out of the window
	liveSpan   = time.Hour
	liveTTL    = time.Minute      // live numbers are re-queried at most this often
	liveErrTTL = 10 * time.Second // a failed query is retried after this
)

// LiveView is the last hour, unsettled.
type LiveView struct {
	From, To   time.Time
	Rows       []MetricRow
	Samples    int
	BaselineOK bool
	At         time.Time
	Err        string
}

type liveEntry struct {
	mu   sync.Mutex
	view *LiveView
}

// blend mixes two baselines: weight w for a, 1-w for b.
func blend(a, b analyze.Metrics, w float64) analyze.Metrics {
	mix := func(x, y int64) int64 { return int64(math.Round(w*float64(x) + (1-w)*float64(y))) }
	m := analyze.Metrics{Total: mix(a.Total, b.Total), Dynamic: mix(a.Dynamic, b.Dynamic), Origin5xx: mix(a.Origin5xx, b.Origin5xx)}
	names := map[string]bool{}
	var order []string
	for _, ws := range [][]analyze.WorkerMetrics{a.Workers, b.Workers} {
		for _, x := range ws {
			if !names[x.Name] {
				names[x.Name] = true
				order = append(order, x.Name)
			}
		}
	}
	for _, n := range order {
		wa, wb := a.Worker(n), b.Worker(n)
		m.Workers = append(m.Workers, analyze.WorkerMetrics{Name: n, Calls: mix(wa.Calls, wb.Calls), CPUP50ms: w*wa.CPUP50ms + (1-w)*wb.CPUP50ms})
	}
	if len(a.Paths) > 0 || len(b.Paths) > 0 {
		m.Paths = map[string]int64{}
		for k := range a.Paths {
			m.Paths[k] = mix(a.Paths[k], b.Paths[k])
		}
		for k := range b.Paths {
			m.Paths[k] = mix(a.Paths[k], b.Paths[k])
		}
	}
	return m
}

// liveBaseline is the 28-day same-hour baseline for [from, from+1h).
func liveBaseline(a Archive, zone config.Zone, from time.Time) (analyze.Metrics, int, bool, error) {
	hA := from.Truncate(time.Hour)
	w := float64(hA.Add(time.Hour).Sub(from)) / float64(time.Hour) // share of the window in hour A
	median := func(h time.Time) (analyze.Metrics, int, error) {
		ss, err := a.SameHourSnapshots(zone.ZoneID, h, h.Add(time.Hour), analyze.LongBaselineDays)
		var ms []analyze.Metrics
		for _, s := range ss {
			ms = append(ms, s.Metrics)
		}
		return analyze.Median(ms), len(ms), err
	}
	mA, nA, err := median(hA)
	if err != nil {
		return analyze.Metrics{}, 0, false, err
	}
	if w >= 0.999 {
		return mA, nA, nA > 0, nil
	}
	mB, nB, err := median(hA.Add(time.Hour))
	if err != nil {
		return analyze.Metrics{}, 0, false, err
	}
	return blend(mA, mB, w), min(nA, nB), nA > 0 && nB > 0, nil
}

// liveView returns the cached live view of a zone, re-querying at most
// once a minute (concurrent viewers share one query).
func (s *Server) liveView(ctx context.Context, z config.Zone) *LiveView {
	if s.Measure == nil {
		return nil
	}
	s.liveMu.Lock()
	e := s.liveCache[z.ZoneID]
	if e == nil {
		e = &liveEntry{}
		s.liveCache[z.ZoneID] = e
	}
	s.liveMu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	now := s.Now()
	// A failure is retried sooner than a success is refreshed: one network
	// hiccup must not hide the live hour for a whole minute.
	ttl := liveTTL
	if e.view != nil && e.view.Err != "" {
		ttl = liveErrTTL
	}
	if e.view != nil && now.Sub(e.view.At) < ttl {
		return e.view
	}
	to := now.Add(-liveLag).Truncate(time.Minute)
	v := &LiveView{From: to.Add(-liveSpan), To: to, At: now}
	qctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cur, err := s.Measure(qctx, z, v.From, v.To)
	if err != nil {
		v.Err = err.Error()
		e.view = v
		return v
	}
	base, n, has, err := liveBaseline(s.Archive, z, v.From)
	if err != nil {
		v.Err = err.Error()
		e.view = v
		return v
	}
	v.Samples, v.BaselineOK = n, n >= analyze.LongBaselineMinSamples
	v.Rows = metricRows(s.Cfg, z, cur, base, has)
	e.view = v
	return v
}
