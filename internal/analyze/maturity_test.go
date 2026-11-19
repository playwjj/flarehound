package analyze

import "testing"

func TestCountSamplesMeasuredZero(t *testing.T) {
	measured := []string{MetricUnreachable}
	s := CountSamples([]Metrics{
		{Total: 1},                                        // archived before v1.15: 52x not measured
		{Total: 1, Measured: measured},                    // measured, and 0: a sample
		{Total: 1, Unreachable: 4},                        // v1.15–v1.16.1 hour with 52x: a sample
		{Total: 1, Origin: &OriginMetrics{Requests: 300}}, // v1.15+ hour with the origin: a sample
		{Total: 1, Workers: []WorkerMetrics{{Name: "w", Calls: 10, CPUP50ms: 1, CPUP99ms: 9}}},
	})
	if s.Hours != 5 || s.Unreachable != 3 || s.Origin != 1 || s.CPUP99["w"] != 1 {
		t.Fatalf("samples = %+v", s)
	}
	// The median keeps a measured 0 and skips the unmeasured hour.
	m := Median([]Metrics{{}, {Measured: measured}, {Measured: measured}, {Unreachable: 30, Measured: measured}})
	if m.Unreachable != 0 || m.Samples == nil || m.Samples.Unreachable != 3 {
		t.Fatalf("median 52x %d, samples %+v", m.Unreachable, m.Samples)
	}
}

func TestHoldImmature(t *testing.T) {
	fs := []Finding{{Rule: RuleUnreachable, Cur: 26}, {Rule: RuleOriginSlow, Subject: OriginTTFB}, {Rule: RuleTotalUp}}
	kept, held := HoldImmature(fs, BaselineSamples{Hours: 28, Unreachable: 1, Origin: 3}, 3)
	if len(kept) != 2 || kept[0].Rule != RuleOriginSlow || kept[1].Rule != RuleTotalUp || len(held) != 1 || held[0].Rule != RuleUnreachable {
		t.Fatalf("kept %v held %v", kept, held)
	}
	// min 0 turns maturity off.
	if kept, held := HoldImmature(fs, BaselineSamples{}, 0); len(kept) != 3 || held != nil {
		t.Fatalf("min 0: kept %v held %v", kept, held)
	}
}

func TestBaselineMaturityAndRipen(t *testing.T) {
	cur := Metrics{Measured: []string{MetricUnreachable}, Workers: []WorkerMetrics{{Name: "w", CPUP99ms: 30}, {Name: "old", CPUP99ms: 20}}}
	s := BaselineSamples{Hours: 28, Unreachable: 2, CPUP99: map[string]int{"w": 1, "old": 20}}
	im := ImmatureMetrics(cur, s, 3)
	if len(im) != 2 || im[0].Metric != MetricUnreachable || im[0].Samples != 2 || im[1].Subject != "w" {
		t.Fatalf("immature = %+v", im)
	}
	// The origin is not measured on this plan: not "accumulating" at all.
	for _, m := range BaselineMaturity(cur, s, 3) {
		if m.Metric == MetricOrigin {
			t.Fatal("unmeasured origin listed")
		}
	}
	base := Metrics{Samples: &s, Workers: []WorkerMetrics{{Name: "w", CPUP50ms: 4, CPUP99ms: 25}, {Name: "old", CPUP50ms: 4, CPUP99ms: 18}}}
	r := Ripen(base, 3)
	if r.Worker("w").CPUP99ms != 0 || r.Worker("old").CPUP99ms != 18 || base.Worker("w").CPUP99ms != 25 {
		t.Fatalf("ripen: %+v (orig %+v)", r.Workers, base.Workers)
	}
	if j := JudgeCPU(WorkerMetrics{CPUP50ms: 8, CPUP99ms: 30}, r.Worker("w")); j.P99Known || j.Verdict != "" {
		t.Fatalf("immature P99 judged: %+v", j)
	}
}
