package analyze

import (
	"testing"

	"github.com/playwjj/flarehound/internal/cfapi"
)

func defaults() Thresholds {
	return Thresholds{
		TotalUpPct: 35, WorkerCallsUpPct: 35, CPUP50UpPct: 25, DynamicUpPct: 50,
		Origin5xxMultiple: 3, Origin5xxMin: 50, NewFaceMinCount: 5000,
		CollapseDownPct: 50, MinCount: 1000, EscalationPct: 25, RecoveryCleanRound: 2,
	}
}

func rules(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Key()] = true
	}
	return m
}

func TestEvaluateIncident(t *testing.T) {
	// The 2026-11-17 shape: Worker calls +52%, CPU P50 +50%, a residential
	// proxy ASN new in the Top 10.
	base := Metrics{
		Total: 100_000, Dynamic: 40_000, Origin5xx: 10,
		Workers: []WorkerMetrics{{Name: "web", Calls: 50_000, CPUP50ms: 4}},
		TopASN:  []cfapi.Face{{Name: "AS4134", ASN: 4134, Count: 30_000}},
		TopUA:   []cfapi.Face{{Name: "Mozilla/5.0 Chrome/130", Count: 40_000}},
	}
	cur := base
	cur.Total = 150_000
	cur.Dynamic = 70_000
	cur.Workers = []WorkerMetrics{{Name: "web", Calls: 76_000, CPUP50ms: 6}}
	cur.TopASN = []cfapi.Face{{Name: "AS4134", ASN: 4134, Count: 30_000}, {Name: "AS207990", ASN: 207990, Count: 40_000}}

	got := rules(Evaluate(cur, base, defaults(), Known{}))
	for _, want := range []string{"total_up", "dynamic_up", "worker_calls_up:web", "cpu_p50_up:web", "new_face_asn:AS207990"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if got["origin_5xx"] || got["collapse_total"] {
		t.Errorf("unexpected findings %v", got)
	}
}

func TestEvaluateQuiet(t *testing.T) {
	m := Metrics{Total: 100_000, Dynamic: 40_000, Workers: []WorkerMetrics{{Name: "w", Calls: 1000, CPUP50ms: 3}}}
	if fs := Evaluate(m, m, defaults(), Known{}); len(fs) != 0 {
		t.Fatalf("identical windows produced %v", fs)
	}
}

func TestMinCountFloor(t *testing.T) {
	// 10 -> 40 requests is +300% but noise on a tiny site.
	if fs := Evaluate(Metrics{Total: 40}, Metrics{Total: 10}, defaults(), Known{}); len(fs) != 0 {
		t.Fatalf("tiny volume fired: %v", fs)
	}
	// Collapse from a tiny baseline is noise too.
	if fs := Evaluate(Metrics{Total: 1}, Metrics{Total: 500}, defaults(), Known{}); len(fs) != 0 {
		t.Fatalf("tiny collapse fired: %v", fs)
	}
	fs := Evaluate(Metrics{Total: 400}, Metrics{Total: 5000}, defaults(), Known{})
	if !rules(fs)["collapse_total"] || !fs[0].Down {
		t.Fatalf("real collapse missed: %v", fs)
	}
}

func TestOrigin5xx(t *testing.T) {
	th := defaults()
	if fs := Evaluate(Metrics{Origin5xx: 40}, Metrics{Origin5xx: 1}, th, Known{}); len(fs) != 0 {
		t.Fatal("below absolute minimum must not fire")
	}
	if fs := Evaluate(Metrics{Origin5xx: 100}, Metrics{Origin5xx: 40}, th, Known{}); len(fs) != 0 {
		t.Fatal("2.5x baseline must not fire")
	}
	if fs := Evaluate(Metrics{Origin5xx: 120}, Metrics{Origin5xx: 40}, th, Known{}); !rules(fs)["origin_5xx"] {
		t.Fatal("3x and > 50 must fire")
	}
}

func TestNewFacesKnownAndOld(t *testing.T) {
	base := Metrics{TopUA: []cfapi.Face{{Name: "old", Count: 9000}}}
	cur := Metrics{TopUA: []cfapi.Face{
		{Name: "old", Count: 9000},
		{Name: "small-new", Count: 100},
		{Name: "MyMonitor/2.0", Count: 9000},
		{Name: "evil/1.0", Count: 9000},
	}, TopASN: []cfapi.Face{{Name: "AS64500", ASN: 64500, Count: 9000}}}
	k := Known{ASNs: map[int]bool{64500: true}, UserAgents: []string{"mymonitor"}}
	got := Evaluate(cur, base, defaults(), k)
	if len(got) != 1 || got[0].Subject != "evil/1.0" {
		t.Fatalf("want only evil/1.0, got %v", got)
	}
}

func TestPathRule(t *testing.T) {
	th := defaults()
	th.PathRules = []PathRule{{Name: "login", UpPct: 100, MinCount: 20}}
	if fs := Evaluate(Metrics{Paths: map[string]int64{"login": 30}}, Metrics{Paths: map[string]int64{"login": 10}}, th, Known{}); !rules(fs)["path_up:login"] {
		t.Fatalf("path rule missed: %v", fs)
	}
	if fs := Evaluate(Metrics{Paths: map[string]int64{"login": 15}}, Metrics{Paths: map[string]int64{"login": 1}}, th, Known{}); len(fs) != 0 {
		t.Fatalf("below path min_count fired: %v", fs)
	}
}

func TestNewFaceUAKeyIsShared(t *testing.T) {
	a := Finding{Rule: RuleNewFaceUA, Subject: "bot/1"}
	b := Finding{Rule: RuleNewFaceUA, Subject: "bot/2"}
	if a.Key() != b.Key() {
		t.Fatal("rotating UAs must map to one signal")
	}
	c := Finding{Rule: RuleNewFaceASN, Subject: "AS1"}
	d := Finding{Rule: RuleNewFaceASN, Subject: "AS2"}
	if c.Key() == d.Key() {
		t.Fatal("distinct ASNs are distinct signals")
	}
}

func TestVerifiedBot(t *testing.T) {
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if _, ok := VerifiedBot(ua, []cfapi.Face{{ASN: 15169, Count: 990}, {ASN: 7922, Count: 10}}); !ok {
		t.Fatal("real Googlebot rejected")
	}
	if _, ok := VerifiedBot(ua, []cfapi.Face{{ASN: 15169, Count: 100}, {ASN: 7922, Count: 900}}); ok {
		t.Fatal("impostor Googlebot from residential ASN accepted")
	}
	if _, ok := VerifiedBot("curl/8.0", []cfapi.Face{{ASN: 15169, Count: 1}}); ok {
		t.Fatal("non-crawler UA verified")
	}
}

func TestHypothesizeNewFaceSurge(t *testing.T) {
	base := Metrics{Total: 100_000}
	cur := Metrics{Total: 150_000}
	fs := []Finding{
		{Rule: RuleTotalUp, Cur: 150_000, Base: 100_000},
		{Rule: RuleNewFaceASN, Subject: "AS207990", Cur: 45_000},
	}
	hs := Hypothesize(cur, base, fs, Attribution{})
	if len(hs) == 0 || hs[0].ID != HypNewFaceSurge || hs[0].Confidence != High || hs[0].Subject != "AS207990" {
		t.Fatalf("got %+v", hs)
	}
}

func TestHypothesizeCheapVolume(t *testing.T) {
	fs := []Finding{{Rule: RuleTotalUp}}
	a := Attribution{
		CacheCur:  []cfapi.Face{{Name: "hit", Count: 140_000}, {Name: "dynamic", Count: 10_000}},
		CacheBase: []cfapi.Face{{Name: "hit", Count: 90_000}, {Name: "dynamic", Count: 10_000}},
	}
	hs := Hypothesize(Metrics{Total: 150_000}, Metrics{Total: 100_000}, fs, a)
	found := false
	for _, h := range hs {
		if h.ID == HypCheapVolume {
			found = true
		}
	}
	if !found {
		t.Fatalf("cheap-volume hypothesis missing: %+v", hs)
	}
}

func TestHypothesizeSlowPath(t *testing.T) {
	fs := []Finding{{Rule: RuleCPUUp, Subject: "web"}}
	hs := Hypothesize(Metrics{}, Metrics{}, fs, Attribution{})
	if len(hs) != 1 || hs[0].ID != HypSlowPath {
		t.Fatalf("got %+v", hs)
	}
}

func TestBlockAdvice(t *testing.T) {
	cur, base := Metrics{Total: 150_000}, Metrics{Total: 100_000}
	adv := Block(cur, base, Attribution{TopIPs: []cfapi.Face{{Name: "203.0.113.7", Count: 20_000}, {Name: "198.51.100.1", Count: 100}}})
	if len(adv.Candidates) != 1 || adv.Candidates[0].IP != "203.0.113.7" || adv.Dispersed {
		t.Fatalf("concentrated: %+v", adv)
	}
	adv = Block(cur, base, Attribution{TopIPs: []cfapi.Face{{Name: "a", Count: 300}, {Name: "b", Count: 200}}})
	if len(adv.Candidates) != 0 || !adv.Dispersed {
		t.Fatalf("dispersed: %+v", adv)
	}
}

func TestPctChange(t *testing.T) {
	if PctChange(0, 0) != 0 || PctChange(5, 0) != 999 || PctChange(150, 100) != 50 {
		t.Fatal("PctChange")
	}
}
