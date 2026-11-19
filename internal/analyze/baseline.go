package analyze

import "sort"

// Long-baseline parameters (SPEC 6 use ①, SPEC 17 "统计基线"): once the
// archive holds enough same-hour samples, a finding must cross its line
// against yesterday AND against the median of the last 28 days' same
// hour. One odd yesterday no longer makes an anomaly, and a slowly
// rising "new normal" stops paging every day.
const (
	LongBaselineDays       = 28
	LongBaselineMinSamples = 20
)

func medianInt(v []int64) int64 {
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

func medianFloat(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// Median builds a baseline whose every metric is the per-metric median
// of the samples, with the measured samples behind each tracked metric
// (Samples: baseline maturity). Top lists are not medianed (new faces are judged
// against yesterday's Top 25 and the archive's face history instead).
func Median(samples []Metrics) Metrics {
	var m Metrics
	var total, dyn, o5, unreach, oreq []int64
	var ttfb, otot, tcp, tls []float64
	var unreachBy []map[string]int64
	calls := map[string][]int64{}
	cpu := map[string][]float64{}
	cpu99 := map[string][]float64{}
	paths := map[string][]int64{}
	var workerOrder []string
	for _, s := range samples {
		total = append(total, s.Total)
		dyn = append(dyn, s.Dynamic)
		o5 = append(o5, s.Origin5xx)
		// Hours archived before v1.15 never measured 52x (nor the origin):
		// they are unknown, not zero, and must not drag the median to 0.
		if MeasuredUnreachable(s) {
			unreach = append(unreach, s.Unreachable)
			unreachBy = append(unreachBy, s.UnreachableBy)
		}
		if o := s.Origin; o != nil && o.Requests > 0 {
			oreq = append(oreq, o.Requests)
			ttfb, otot = append(ttfb, o.TTFBP95ms), append(otot, o.TotalP95ms)
			tcp, tls = append(tcp, o.TCPP95ms), append(tls, o.TLSP95ms)
		}
		for _, w := range s.Workers {
			if _, seen := calls[w.Name]; !seen {
				workerOrder = append(workerOrder, w.Name)
			}
			calls[w.Name] = append(calls[w.Name], w.Calls)
			cpu[w.Name] = append(cpu[w.Name], w.CPUP50ms)
			if w.CPUP99ms > 0 { // hours archived before v1.16 have no P99
				cpu99[w.Name] = append(cpu99[w.Name], w.CPUP99ms)
			}
		}
		for k, v := range s.Paths {
			paths[k] = append(paths[k], v)
		}
	}
	cnt := CountSamples(samples)
	m.Samples = &cnt
	m.Total, m.Dynamic, m.Origin5xx = medianInt(total), medianInt(dyn), medianInt(o5)
	m.Unreachable = medianInt(unreach)
	// Per-status medians, so the baseline's mix (522/524 or not) is known.
	keys := map[string]bool{}
	for _, by := range unreachBy {
		for k := range by {
			keys[k] = true
		}
	}
	for k := range keys {
		vs := make([]int64, 0, len(unreachBy))
		for _, by := range unreachBy {
			vs = append(vs, by[k])
		}
		if v := medianInt(vs); v > 0 {
			if m.UnreachableBy == nil {
				m.UnreachableBy = map[string]int64{}
			}
			m.UnreachableBy[k] = v
		}
	}
	// Only hours that measured the origin count (older archived hours
	// predate the measurement).
	if len(oreq) > 0 {
		m.Origin = &OriginMetrics{Requests: medianInt(oreq), TTFBP95ms: medianFloat(ttfb), TotalP95ms: medianFloat(otot),
			TCPP95ms: medianFloat(tcp), TLSP95ms: medianFloat(tls)}
	}
	for _, name := range workerOrder {
		wm := WorkerMetrics{Name: name, Calls: medianInt(calls[name]), CPUP50ms: medianFloat(cpu[name])}
		if len(cpu99[name]) > 0 {
			wm.CPUP99ms = medianFloat(cpu99[name])
		}
		m.Workers = append(m.Workers, wm)
	}
	if len(paths) > 0 {
		m.Paths = map[string]int64{}
		for k, v := range paths {
			m.Paths[k] = medianInt(v)
		}
	}
	return m
}

// CrossCheck keeps a finding only if the long baseline confirms it (a
// finding with the same key fired against the median). New-face findings
// pass through: they are judged by face history, not by volume medians.
func CrossCheck(vsYesterday, vsLong []Finding) []Finding {
	confirmed := map[string]bool{}
	for _, f := range vsLong {
		confirmed[f.Key()] = true
	}
	out := vsYesterday[:0:0]
	for _, f := range vsYesterday {
		if f.Rule == RuleNewFaceUA || f.Rule == RuleNewFaceASN || confirmed[f.Key()] {
			out = append(out, f)
		}
	}
	return out
}
