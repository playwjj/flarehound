// Package analyze compares a current metrics window with a baseline window
// (yesterday, same hours) and applies FlareHound's detection rules.
//
// The defaults encode the alert discipline from SPEC.md section 7:
// thresholds first, attribution before conclusions, expensive traffic
// (dynamic responses, Worker renders) reported separately from cheap
// edge volume.
package analyze

import (
	"fmt"
	"math"
	"sort"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// Thresholds mirrors config.Thresholds; duplicated here so this package
// stays independent of the config file format.
type Thresholds struct {
	TotalUpPct         float64
	WorkerCallsUpPct   float64
	CPUP50UpPct        float64
	DynamicUpPct       float64
	Origin5xxMultiple  float64
	Origin5xxMin       int64
	NewFaceMinCount    int64
	CollapseDownPct    float64
	EscalationPct      float64
	RecoveryCleanRound int
}

// Metrics is one window's worth of observations for one zone (+ its
// primary Worker). For the baseline window, TopUA/TopASN must be the
// Top 25 ("old faces"); for the current window, the Top 10.
type Metrics struct {
	Total       int64
	Dynamic     int64
	Origin5xx   int64
	WorkerCalls int64
	CPUP50ms    float64
	TopUA       []cfapi.Face
	TopASN      []cfapi.Face
}

// Finding is one triggered rule, with the numbers that triggered it.
type Finding struct {
	Rule    string
	Summary string
}

// PctChange returns the percentage change from base to cur. A zero base
// with a positive current value is reported as +999 (effectively "new").
func PctChange(cur, base float64) float64 {
	if base == 0 {
		if cur == 0 {
			return 0
		}
		return 999
	}
	return (cur - base) / base * 100
}

func up(rule string, cur, base int64, pct float64) Finding {
	return Finding{Rule: rule, Summary: fmt.Sprintf("%s: %d vs %d (%+.1f%%)", rule, cur, base, pct)}
}

// Evaluate applies every detection rule and returns the findings.
// An empty result means the window is clean.
func Evaluate(cur, base Metrics, th Thresholds) []Finding {
	var out []Finding

	if p := PctChange(float64(cur.Total), float64(base.Total)); p >= th.TotalUpPct {
		out = append(out, up("total_up", cur.Total, base.Total, p))
	}
	if p := PctChange(float64(cur.WorkerCalls), float64(base.WorkerCalls)); p >= th.WorkerCallsUpPct {
		out = append(out, up("worker_calls_up", cur.WorkerCalls, base.WorkerCalls, p))
	}
	if p := PctChange(cur.CPUP50ms, base.CPUP50ms); p >= th.CPUP50UpPct {
		out = append(out, Finding{Rule: "cpu_p50_up",
			Summary: fmt.Sprintf("cpu_p50_up: %.1f ms vs %.1f ms (%+.1f%%)", cur.CPUP50ms, base.CPUP50ms, p)})
	}
	if p := PctChange(float64(cur.Dynamic), float64(base.Dynamic)); p >= th.DynamicUpPct {
		out = append(out, up("dynamic_up", cur.Dynamic, base.Dynamic, p))
	}
	if float64(cur.Origin5xx) >= float64(base.Origin5xx)*th.Origin5xxMultiple && cur.Origin5xx > th.Origin5xxMin {
		out = append(out, Finding{Rule: "origin_5xx",
			Summary: fmt.Sprintf("origin_5xx: %d vs %d (%.0fx, above min %d)", cur.Origin5xx, base.Origin5xx, ratio(cur.Origin5xx, base.Origin5xx), th.Origin5xxMin)})
	}
	if p := PctChange(float64(cur.Total), float64(base.Total)); p <= -th.CollapseDownPct {
		out = append(out, up("collapse_total", cur.Total, base.Total, p))
	}
	if p := PctChange(float64(cur.WorkerCalls), float64(base.WorkerCalls)); p <= -th.CollapseDownPct {
		out = append(out, up("collapse_worker", cur.WorkerCalls, base.WorkerCalls, p))
	}

	out = append(out, newFaces("ua", cur.TopUA, base.TopUA, th.NewFaceMinCount)...)
	out = append(out, newFaces("asn", cur.TopASN, base.TopASN, th.NewFaceMinCount)...)
	return out
}

func ratio(cur, base int64) float64 {
	if base == 0 {
		return math.Inf(1)
	}
	return float64(cur) / float64(base)
}

// newFaces flags Top-10 entries absent from the baseline Top-25 list.
//
// Known false-positive class (SPEC.md 7.3): legitimate crawlers bump
// their UA version strings and look "new". Before treating a new UA as
// hostile, verify it by ASN (e.g. Googlebot lives on AS15169). This
// function only reports; attribution happens in the report layer.
func newFaces(kind string, curTop, baseTop []cfapi.Face, minCount int64) []Finding {
	known := make(map[string]bool, len(baseTop))
	for _, f := range baseTop {
		known[f.Name] = true
	}
	var out []Finding
	for _, f := range curTop {
		if f.Count > minCount && !known[f.Name] {
			name := f.Name
			if len(name) > 80 {
				name = name[:80] + "…"
			}
			out = append(out, Finding{Rule: "new_face_" + kind,
				Summary: fmt.Sprintf("new_face_%s: %s (%d in window)", kind, name, f.Count)})
		}
	}
	return out
}

// Fingerprint identifies an anomaly by its sorted rule set, so the state
// machine can tell "the same anomaly continuing" from a new one.
func Fingerprint(findings []Finding) string {
	rules := make([]string, 0, len(findings))
	seen := map[string]bool{}
	for _, f := range findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			rules = append(rules, f.Rule)
		}
	}
	sort.Strings(rules)
	s := ""
	for i, r := range rules {
		if i > 0 {
			s += ","
		}
		s += r
	}
	return s
}
