package analyze

import "testing"

func TestMedian(t *testing.T) {
	m := Median([]Metrics{
		{Total: 100, Workers: []WorkerMetrics{{Name: "w", Calls: 10, CPUP50ms: 1}}, Paths: map[string]int64{"login": 1}},
		{Total: 300, Workers: []WorkerMetrics{{Name: "w", Calls: 30, CPUP50ms: 3}}, Paths: map[string]int64{"login": 3}},
		{Total: 5000, Workers: []WorkerMetrics{{Name: "w", Calls: 9000, CPUP50ms: 90}}, Paths: map[string]int64{"login": 900}}, // outlier day
	})
	if m.Total != 300 || m.Worker("w").Calls != 30 || m.Worker("w").CPUP50ms != 3 || m.Paths["login"] != 3 {
		t.Fatalf("median = %+v", m)
	}
	if e := Median([]Metrics{{Total: 1}, {Total: 4}}); e.Total != 2 {
		t.Fatalf("even median = %d", e.Total)
	}
}

func TestCrossCheck(t *testing.T) {
	y := []Finding{{Rule: RuleTotalUp}, {Rule: RuleDynamicUp}, {Rule: RuleNewFaceASN, Subject: "AS1"}}
	l := []Finding{{Rule: RuleDynamicUp}}
	got := rules(CrossCheck(y, l))
	if got[RuleTotalUp] || !got[RuleDynamicUp] || !got["new_face_asn:AS1"] {
		t.Fatalf("got %v", got)
	}
}
