package analyze

import "testing"

func originTh() Thresholds {
	th := defaults()
	th.OriginSlowUpPct, th.OriginSlowMinMs, th.UnreachableMin = 100, 1000, 10
	return th
}

func TestUnreachable(t *testing.T) {
	th := originTh()
	if fs := Evaluate(Metrics{Unreachable: 9}, Metrics{}, th, Known{}); len(fs) != 0 {
		t.Fatal("below the floor must not fire")
	}
	fs := Evaluate(Metrics{Unreachable: 12}, Metrics{}, th, Known{})
	if !rules(fs)[RuleUnreachable] {
		t.Fatalf("52x from a healthy baseline must fire: %v", fs)
	}
	if s := Assess(Metrics{}, Metrics{}, fs); s.Level != SevHigh {
		t.Fatalf("an unreachable origin is never 'just loud': %+v", s)
	}
	if hs := Hypothesize(Metrics{}, Metrics{}, fs, Attribution{}); len(hs) != 1 || hs[0].ID != HypOriginDown || hs[0].Confidence != High {
		t.Fatalf("hypotheses %+v", hs)
	}
	if fs := Evaluate(Metrics{Unreachable: 15}, Metrics{Unreachable: 10}, th, Known{}); len(fs) != 0 {
		t.Fatal("under 2x an already-flapping baseline must not fire again")
	}
	th.UnreachableMin = 0
	if fs := Evaluate(Metrics{}, Metrics{}, th, Known{}); len(fs) != 0 {
		t.Fatal("a zero floor must still need at least one 52x")
	}
}

func TestOriginSlow(t *testing.T) {
	th := originTh()
	base := Metrics{Origin: &OriginMetrics{Requests: 5000, TTFBP95ms: 464, TotalP95ms: 803}}
	slow := func(ttfb, total float64, reqs int64) Metrics {
		return Metrics{Origin: &OriginMetrics{Requests: reqs, TTFBP95ms: ttfb, TotalP95ms: total}}
	}
	if fs := Evaluate(slow(950, 1200, 5000), base, th, Known{}); len(fs) != 0 {
		t.Fatalf("doubled but under the 1 s floor must not fire: %v", fs)
	}
	fs := Evaluate(slow(1400, 1800, 5000), base, th, Known{})
	if len(fs) != 1 || fs[0].Key() != "origin_slow:ttfb" {
		t.Fatalf("slow first byte must fire once (not again as total): %v", fs)
	}
	if hs := Hypothesize(Metrics{}, Metrics{}, fs, Attribution{}); len(hs) != 1 || hs[0].ID != HypOriginSlow {
		t.Fatalf("slow with load flat: %+v", hs)
	}
	withLoad := append(fs, Finding{Rule: RuleDynamicUp})
	hs := Hypothesize(Metrics{}, Metrics{}, withLoad, Attribution{})
	found := false
	for _, h := range hs {
		found = found || h.ID == HypOriginLoad
		if h.ID == HypOriginSlow {
			t.Fatalf("more load must not be blamed on the machine: %+v", hs)
		}
	}
	if !found {
		t.Fatalf("slow under more uncached load: %+v", hs)
	}
	if fs := Evaluate(slow(500, 2500, 5000), base, th, Known{}); len(fs) != 1 || fs[0].Subject != OriginTotal {
		t.Fatalf("transfer slower, first byte steady: %v", fs)
	}
	if fs := Evaluate(slow(1400, 1800, 50), base, th, Known{}); len(fs) != 0 {
		t.Fatal("a P95 over a handful of requests is noise")
	}
	if fs := Evaluate(slow(1400, 1800, 5000), Metrics{}, th, Known{}); len(fs) != 0 {
		t.Fatal("no baseline latency (older archive hours): no finding")
	}
}

func TestMedianOrigin(t *testing.T) {
	m := Median([]Metrics{
		{Unreachable: 0},
		{Unreachable: 4, Origin: &OriginMetrics{Requests: 100, TTFBP95ms: 300}},
		{Unreachable: 0, Origin: &OriginMetrics{Requests: 300, TTFBP95ms: 500}},
		{Unreachable: 0, Origin: &OriginMetrics{Requests: 200, TTFBP95ms: 400}},
	})
	if m.Unreachable != 0 || m.Origin == nil || m.Origin.TTFBP95ms != 400 || m.Origin.Requests != 200 {
		t.Fatalf("median %+v %+v", m, m.Origin)
	}
	if Median([]Metrics{{Total: 1}}).Origin != nil {
		t.Fatal("hours without origin data must not fake a 0 ms baseline")
	}
}

func TestOrigin5xxRate(t *testing.T) {
	if _, ok := (Metrics{Origin5xx: 5}).Origin5xxRate(); ok {
		t.Fatal("unknown without origin requests")
	}
	if r, ok := (Metrics{Origin5xx: 50, Origin: &OriginMetrics{Requests: 1000}}).Origin5xxRate(); !ok || r != 0.05 {
		t.Fatalf("rate %v %v", r, ok)
	}
}
