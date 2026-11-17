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
// of the samples. Top lists are not medianed (new faces are judged
// against yesterday's Top 25 and the archive's face history instead).
func Median(samples []Metrics) Metrics {
	var m Metrics
	var total, dyn, o5 []int64
	calls := map[string][]int64{}
	cpu := map[string][]float64{}
	paths := map[string][]int64{}
	var workerOrder []string
	for _, s := range samples {
		total = append(total, s.Total)
		dyn = append(dyn, s.Dynamic)
		o5 = append(o5, s.Origin5xx)
		for _, w := range s.Workers {
			if _, seen := calls[w.Name]; !seen {
				workerOrder = append(workerOrder, w.Name)
			}
			calls[w.Name] = append(calls[w.Name], w.Calls)
			cpu[w.Name] = append(cpu[w.Name], w.CPUP50ms)
		}
		for k, v := range s.Paths {
			paths[k] = append(paths[k], v)
		}
	}
	m.Total, m.Dynamic, m.Origin5xx = medianInt(total), medianInt(dyn), medianInt(o5)
	for _, name := range workerOrder {
		m.Workers = append(m.Workers, WorkerMetrics{Name: name, Calls: medianInt(calls[name]), CPUP50ms: medianFloat(cpu[name])})
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
