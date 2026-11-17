// Package calibrate compares FlareHound's numbers (adaptive analytics)
// with the Cloudflare dashboard's (SPEC 15, v1.0). The two are different
// datasets: adaptive counts are sampled and include Worker subrequests and
// cache operations, so they routinely run above the dashboard. Thresholds
// are in adaptive units; calibration tells the user by how much, so nobody
// compares an alert's numbers with the dashboard and concludes it is wrong.
package calibrate

import (
	"sort"
	"time"
)

// Day is one UTC day in both datasets.
type Day struct {
	Date time.Time `json:"date"`
	// Dashboard (httpRequests1dGroups)
	DashRequests int64 `json:"dash_requests"`
	DashCached   int64 `json:"dash_cached"`
	Dash5xx      int64 `json:"dash_5xx"`
	// Adaptive (httpRequestsAdaptiveGroups) — what FlareHound reads
	AdRequests     int64   `json:"ad_requests"`
	AdCached       int64   `json:"ad_cached"`
	Ad5xx          int64   `json:"ad_5xx"`
	SampleInterval float64 `json:"sample_interval"`
}

func ratio(a, b int64) (float64, bool) {
	if b <= 0 {
		return 0, false
	}
	return float64(a) / float64(b), true
}

// Verdicts on the request ratio.
const (
	Aligned     = "aligned"       // within ±15 %
	AdaptiveHi  = "adaptive_high" // adaptive counts more: subrequests / cache operations
	AdaptiveLow = "adaptive_low"  // adaptive counts less: unusual, check sampling / ingestion
	NoData      = "no_data"
)

// Summary is the calibration over several days (medians, robust to one
// odd day).
type Summary struct {
	Days          []Day   `json:"days"`
	Requests      float64 `json:"ratio_requests"` // adaptive / dashboard
	Cached        float64 `json:"ratio_cached"`
	Edge5xx       float64 `json:"ratio_5xx"`
	HasCached     bool    `json:"has_cached"`
	Has5xx        bool    `json:"has_5xx"`
	SampleRate    float64 `json:"sample_rate"` // 1 / median sample interval (1 = unsampled)
	Verdict       string  `json:"verdict"`
	MinCountDash  int64   `json:"min_count_dash"` // the min_count threshold in dashboard units
	MinCountAdapt int64   `json:"min_count_adaptive"`
}

func median(v []float64) float64 {
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

// Summarize computes the medians. minCount is the configured min_count
// (adaptive units), translated into dashboard units for the reader.
func Summarize(days []Day, minCount int64) Summary {
	s := Summary{Days: days, MinCountAdapt: minCount}
	var rq, rc, r5, si []float64
	for _, d := range days {
		if r, ok := ratio(d.AdRequests, d.DashRequests); ok {
			rq = append(rq, r)
		}
		// Small numbers make wild ratios: only compare meaningful volumes.
		if d.DashCached >= 100 {
			if r, ok := ratio(d.AdCached, d.DashCached); ok {
				rc = append(rc, r)
			}
		}
		if d.Dash5xx >= 50 {
			if r, ok := ratio(d.Ad5xx, d.Dash5xx); ok {
				r5 = append(r5, r)
			}
		}
		if d.SampleInterval > 0 {
			si = append(si, d.SampleInterval)
		}
	}
	if len(rq) == 0 {
		s.Verdict = NoData
		return s
	}
	s.Requests = median(rq)
	s.Cached, s.HasCached = median(rc), len(rc) > 0
	s.Edge5xx, s.Has5xx = median(r5), len(r5) > 0
	if m := median(si); m > 0 {
		s.SampleRate = 1 / m
	}
	switch {
	case s.Requests > 1.15:
		s.Verdict = AdaptiveHi
	case s.Requests < 0.85:
		s.Verdict = AdaptiveLow
	default:
		s.Verdict = Aligned
	}
	if s.Requests > 0 {
		s.MinCountDash = int64(float64(minCount) / s.Requests)
	}
	return s
}
