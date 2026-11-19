package analyze

import "slices"

// ---- baseline maturity ----
//
// A line read against the archive's same-hour median is only as good as
// the measured hours behind that median. Right after a metric is added
// (52x in v1.15, the origin's latency, the CPU P99 in v1.16) the archive
// holds weeks of hours that never measured it and a handful that did:
// the median then rests on one or two hours, or on none (reads 0), and
// any ordinary hour clears "≥ min and ≥ 2× baseline". Such a baseline is
// immature: its lines do not fire, the console shows it as accumulating,
// and once enough measured hours are in the archive the line takes over
// on its own.

// Metrics whose baseline maturity is tracked (the archive-relative lines
// added after the archive existed). Further lines join here.
const (
	MetricUnreachable = "unreachable" // edge 52x: origin_unreachable and its bookkeeping judgement
	MetricOrigin      = "origin"      // origin answered requests and latency: origin_slow
	MetricCPUP99      = "cpu_p99"     // a Worker's CPU tail: the P50 rise's check
)

// DefaultBaselineMinSamples is how many measured same-hour samples (one
// per day: the same slot on earlier days) a baseline needs before its
// lines may fire (thresholds.baseline_min_samples).
const DefaultBaselineMinSamples = 3

// BaselineSamples is, for an archive baseline, how many of its same-hour
// samples measured each tracked metric.
type BaselineSamples struct {
	Hours       int            // archived same-hour samples
	Unreachable int            // … that measured the edge 52x
	Origin      int            // … that measured the origin's answered requests
	CPUP99      map[string]int // Worker → samples that measured its CPU P99
}

// MeasuredUnreachable reports whether a window measured the edge 52x.
// Windows fetched since v1.16.2 say so explicitly (Measured), which keeps
// a measured 0 a sample; older ones are read by what they hold — a 52x
// count or an origin measurement only exists from v1.15 on.
func MeasuredUnreachable(m Metrics) bool {
	if m.Measured != nil {
		return slices.Contains(m.Measured, MetricUnreachable)
	}
	return m.Unreachable > 0 || len(m.UnreachableBy) > 0 || m.Origin != nil
}

// CountSamples counts, per tracked metric, the samples that measured it.
func CountSamples(samples []Metrics) BaselineSamples {
	s := BaselineSamples{Hours: len(samples)}
	for _, m := range samples {
		if MeasuredUnreachable(m) {
			s.Unreachable++
		}
		if m.Origin != nil && m.Origin.Requests > 0 {
			s.Origin++
		}
		for _, w := range m.Workers {
			if w.CPUP99ms > 0 {
				if s.CPUP99 == nil {
					s.CPUP99 = map[string]int{}
				}
				s.CPUP99[w.Name]++
			}
		}
	}
	return s
}

// Of returns the measured samples behind one metric (subject: the Worker
// for MetricCPUP99).
func (s BaselineSamples) Of(metric, subject string) int {
	switch metric {
	case MetricUnreachable:
		return s.Unreachable
	case MetricOrigin:
		return s.Origin
	case MetricCPUP99:
		return s.CPUP99[subject]
	}
	return s.Hours
}

// Maturity is the baseline of one tracked metric.
type Maturity struct {
	Metric  string // MetricUnreachable | MetricOrigin | MetricCPUP99
	Subject string // the Worker, for MetricCPUP99
	Samples int    // measured same-hour samples so far
	Need    int    // samples it needs
}

// Ripe reports whether the baseline has its samples.
func (m Maturity) Ripe() bool { return m.Samples >= m.Need }

// BaselineMaturity lists the tracked metrics that cur measures, with the
// samples behind each. A metric cur does not measure (a plan without the
// origin's quantiles) is left out: it is not accumulating, it never will.
func BaselineMaturity(cur Metrics, s BaselineSamples, min int) []Maturity {
	var out []Maturity
	add := func(metric, subject string) {
		out = append(out, Maturity{Metric: metric, Subject: subject, Samples: s.Of(metric, subject), Need: min})
	}
	if MeasuredUnreachable(cur) {
		add(MetricUnreachable, "")
	}
	if cur.Origin != nil && cur.Origin.Requests > 0 {
		add(MetricOrigin, "")
	}
	for _, w := range cur.Workers {
		if w.CPUP99ms > 0 {
			add(MetricCPUP99, w.Name)
		}
	}
	return out
}

// ImmatureMetrics is BaselineMaturity restricted to the metrics still
// accumulating.
func ImmatureMetrics(cur Metrics, s BaselineSamples, min int) []Maturity {
	var out []Maturity
	for _, m := range BaselineMaturity(cur, s, min) {
		if !m.Ripe() {
			out = append(out, m)
		}
	}
	return out
}

// RuleMetric is the tracked metric an archive-relative rule rests on
// ("" for rules that rest on none).
func RuleMetric(rule string) string {
	switch rule {
	case RuleUnreachable:
		return MetricUnreachable
	case RuleOriginSlow:
		return MetricOrigin
	}
	return ""
}

// Mature reports whether a finding's baseline is mature: findings of
// rules that rest on no tracked metric always are.
func Mature(f Finding, s BaselineSamples, min int) bool {
	m := RuleMetric(f.Rule)
	return m == "" || min <= 0 || s.Of(m, f.Subject) >= min
}

// HoldImmature splits findings into those whose baseline is mature and
// those held back because it is still accumulating. Held findings are
// not alerts: they are logged, never sent.
func HoldImmature(fs []Finding, s BaselineSamples, min int) (kept, held []Finding) {
	kept = fs[:0:0]
	for _, f := range fs {
		if Mature(f, s, min) {
			kept = append(kept, f)
		} else {
			held = append(held, f)
		}
	}
	return kept, held
}

// Ripen blanks what an immature baseline cannot vouch for, where "not
// measured" has a spelling: a Worker's CPU P99 with fewer than min
// samples reads 0, so the CPU check says "P99 not measured" instead of
// judging against one or two hours. (The 52x and origin lines cannot be
// blanked — 0 is a real baseline there — and are held by HoldImmature
// and the console's accumulating state instead.)
func Ripen(m Metrics, min int) Metrics {
	if m.Samples == nil || min <= 0 {
		return m
	}
	var ws []WorkerMetrics
	for _, w := range m.Workers {
		if w.CPUP99ms > 0 && m.Samples.CPUP99[w.Name] < min {
			w.CPUP99ms = 0
		}
		ws = append(ws, w)
	}
	m.Workers = ws
	return m
}
