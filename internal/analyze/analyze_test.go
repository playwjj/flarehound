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
	if v := VerifiedBot(ua, []cfapi.Face{{ASN: 15169, Count: 990}, {ASN: 7922, Count: 10}}); !v.Verified || v.Impostor() {
		t.Fatalf("real Googlebot rejected: %+v", v)
	}
	v := VerifiedBot(ua, []cfapi.Face{{ASN: 15169, Count: 100}, {ASN: 7922, Count: 900}})
	if v.Verified || !v.Impostor() || v.Crawler != "Googlebot" || v.Share != 0.1 {
		t.Fatalf("impostor Googlebot from residential ASN: %+v", v)
	}
	if v := VerifiedBot("curl/8.0", []cfapi.Face{{ASN: 15169, Count: 1}}); v.Verified || v.Impostor() {
		t.Fatal("non-crawler UA judged")
	}
	if v := VerifiedByCategory(ua, nil); v.Impostor() {
		t.Fatal("no data must not brand an impostor")
	}
	if v := VerifiedByCategory(ua, []cfapi.Face{{Name: "", Count: 95}, {Name: "Search Engine Crawler", Count: 5}}); !v.Impostor() {
		t.Fatal("unverified by Cloudflare must be an impostor")
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
	adv := Block(cur, base, Attribution{TopIPs: []cfapi.Face{{Name: "203.0.113.7", Count: 20_000}, {Name: "198.51.100.1", Count: 100}}}, nil)
	if len(adv.Candidates) != 1 || adv.Candidates[0].IP != "203.0.113.7" || adv.Dispersed {
		t.Fatalf("concentrated: %+v", adv)
	}
	adv = Block(cur, base, Attribution{TopIPs: []cfapi.Face{{Name: "a", Count: 300}, {Name: "b", Count: 200}}}, nil)
	if len(adv.Candidates) != 0 || !adv.Dispersed {
		t.Fatalf("dispersed: %+v", adv)
	}
}

func TestPctChange(t *testing.T) {
	if PctChange(0, 0) != 0 || PctChange(5, 0) != 999 || PctChange(150, 100) != 50 {
		t.Fatal("PctChange")
	}
}

func TestBlockExcludesProtected(t *testing.T) {
	cur, base := Metrics{Total: 150_000}, Metrics{Total: 100_000}
	protect := func(ip string) (string, bool) {
		if ip == "2a06:98c0:3600::103" {
			return "Cloudflare range 2a06:98c0::/29", true
		}
		return "", false
	}
	adv := Block(cur, base, Attribution{TopIPs: []cfapi.Face{
		{Name: "2a06:98c0:3600::103", Count: 39_500}, {Name: "45.13.7.9", Count: 3_000}, {Name: "45.13.7.10", Count: 200}}}, protect)
	if len(adv.Excluded) != 1 || !adv.Excluded[0].Cloudflare || adv.Excluded[0].Share < 0.78 {
		t.Fatalf("excluded %+v", adv.Excluded)
	}
	if len(adv.Candidates) != 1 || adv.Candidates[0].IP != "45.13.7.9" {
		t.Fatalf("candidates %+v", adv.Candidates)
	}
	if adv.Dispersed {
		t.Fatal("dispersion must be judged on blockable IPs only")
	}
}

func TestNoCandidatesWithoutExcess(t *testing.T) {
	// The live case: origin 5xx on -3.9% traffic must not name IPs.
	adv := Block(Metrics{Total: 1290}, Metrics{Total: 1343}, Attribution{TopIPs: []cfapi.Face{{Name: "171.83.47.36", Count: 509}}}, nil)
	if len(adv.Candidates) != 0 || adv.Dispersed {
		t.Fatalf("%+v", adv)
	}
}

func TestRouteBugHypothesis(t *testing.T) {
	fs := []Finding{{Rule: RuleOrigin5xx, Cur: 52}}
	hs := Hypothesize(Metrics{}, Metrics{}, fs, Attribution{Origin5xxPaths: []cfapi.Face{{Name: "/api/x", Count: 50}, {Name: "/", Count: 2}}})
	if len(hs) != 1 || hs[0].ID != HypRouteBug || hs[0].Subject != "/api/x" {
		t.Fatalf("%+v", hs)
	}
	hs = Hypothesize(Metrics{}, Metrics{}, fs, Attribution{Origin5xxPaths: []cfapi.Face{{Name: "/a", Count: 10}, {Name: "/b", Count: 9}}})
	if hs[0].ID != HypOriginFailure {
		t.Fatalf("%+v", hs)
	}
}

func TestAssessEdgeAbsorbedFlood(t *testing.T) {
	// The field case: total +249%, Worker calls up, dynamic flat, CPU down.
	base := Metrics{Total: 100_000, Dynamic: 30_000}
	cur := Metrics{Total: 349_000, Dynamic: 30_300}
	fs := []Finding{{Rule: RuleTotalUp}, {Rule: RuleWorkerCallsUp, Subject: "web"}}
	if s := Assess(cur, base, fs); s.Level != SevLow || s.Kind != EdgeAbsorbed {
		t.Fatalf("%+v", s)
	}
	// Real rendering up: it hurts.
	if s := Assess(Metrics{Total: 349_000, Dynamic: 60_000}, base, fs); s.Level != SevHigh {
		t.Fatalf("%+v", s)
	}
	// Any expensive signal makes it high.
	if s := Assess(cur, base, append(fs, Finding{Rule: RuleCPUUp})); s.Level != SevHigh {
		t.Fatalf("%+v", s)
	}
	if s := Assess(cur, base, nil); s.Level != "" {
		t.Fatal("no findings, no severity")
	}
}

// The 2026-11-19 01:07 field case: CPU P50 +50.5% after a flood receded,
// P99 +12%, calls −18% — a mix change, not a cost rise.
func TestCPUMixChange(t *testing.T) {
	base := Metrics{Dynamic: 30_000, Workers: []WorkerMetrics{{Name: "web", Calls: 100_000, CPUP50ms: 2.0, CPUP99ms: 25.0}}}
	cur := Metrics{Dynamic: 30_000, Workers: []WorkerMetrics{{Name: "web", Calls: 82_000, CPUP50ms: 3.01, CPUP99ms: 28.0}}}
	j := JudgeCPU(cur.Worker("web"), base.Worker("web"))
	if j.Verdict != CPUMix || !j.P99Known || j.P99Pct < 11.9 || j.P99Pct > 12.1 || j.CallsPct != -18 {
		t.Fatalf("%+v", j)
	}
	fs := []Finding{{Rule: RuleCPUUp, Subject: "web", Cur: 3.01, Base: 2, Pct: 50.5}}
	if s := Assess(cur, base, fs); s.Level != SevLow || s.Kind != CPUMixKind {
		t.Fatalf("mix must be reported one level down: %+v", s)
	}
	hs := Hypothesize(cur, base, fs, Attribution{})
	if len(hs) != 1 || hs[0].ID != HypCPUMix {
		t.Fatalf("%+v", hs)
	}
	// Another expensive line keeps the round high.
	if s := Assess(cur, base, append(fs, Finding{Rule: RuleOrigin5xx})); s.Level != SevHigh {
		t.Fatalf("%+v", s)
	}

	// Tail up with the median, calls held: really more expensive.
	cur2 := Metrics{Dynamic: 30_000, Workers: []WorkerMetrics{{Name: "web", Calls: 98_000, CPUP50ms: 3.0, CPUP99ms: 40.0}}}
	if j := JudgeCPU(cur2.Worker("web"), base.Worker("web")); j.Verdict != CPUCostly {
		t.Fatalf("%+v", j)
	}
	if s := Assess(cur2, base, fs); s.Level != SevHigh {
		t.Fatalf("%+v", s)
	}
	if hs := Hypothesize(cur2, base, fs, Attribution{}); len(hs) != 1 || hs[0].ID != HypCPUCostly {
		t.Fatalf("%+v", hs)
	}

	// No P99 on one side (an hour archived before v1.16): undecided, the
	// old reading stays.
	old := Metrics{Dynamic: 30_000, Workers: []WorkerMetrics{{Name: "web", Calls: 100_000, CPUP50ms: 2.0}}}
	if j := JudgeCPU(cur.Worker("web"), old.Worker("web")); j.Verdict != "" || j.P99Known {
		t.Fatalf("%+v", j)
	}
	if s := Assess(cur, old, fs); s.Level != SevHigh {
		t.Fatalf("%+v", s)
	}
}

func TestMedianP99(t *testing.T) {
	m := Median([]Metrics{
		{Workers: []WorkerMetrics{{Name: "web", Calls: 1, CPUP50ms: 1, CPUP99ms: 10}}},
		{Workers: []WorkerMetrics{{Name: "web", Calls: 1, CPUP50ms: 1}}}, // pre-v1.16 hour
		{Workers: []WorkerMetrics{{Name: "web", Calls: 1, CPUP50ms: 1, CPUP99ms: 20}}},
	})
	if got := m.Worker("web").CPUP99ms; got != 15 {
		t.Fatalf("P99 median over measured hours only: %v", got)
	}
}

// starngage, v1.15/v1.16 field data: ~10,000 edge 52x a day, 522/524
// only, while real origin 5xx were 213 and the site was fine; skoolopedia
// (Free) has a thin 530-led trickle that must keep the plain reading.
func TestJudgeUnreachable(t *testing.T) {
	const min = 10
	bg := func(n522, n524, other int64, origin int64) Metrics {
		m := Metrics{Unreachable: n522 + n524 + other, UnreachableBy: map[string]int64{}, Origin: &OriginMetrics{Requests: origin}}
		for k, v := range map[string]int64{"522": n522, "524": n524, "521": other} {
			if v > 0 {
				m.UnreachableBy[k] = v
			}
		}
		return m
	}
	base := bg(220, 240, 0, 17_000)

	// Steady state (the 13:37 tile: 83 in the hour against a ~460 background).
	for _, cur := range []Metrics{bg(40, 43, 0, 16_000), bg(222, 240, 0, 17_500), bg(500, 420, 0, 16_000)} {
		fire, c := UnreachableFires(cur, base, min)
		if fire || c.Verdict != UnreachBook {
			t.Fatalf("background read as %+v (fire %v) for %+v", c, fire, cur.UnreachableBy)
		}
	}
	// Volume jump ≥ 3×.
	if fire, c := UnreachableFires(bg(900, 600, 0, 16_000), base, min); !fire || c.Verdict != UnreachIncident || !c.JumpHit {
		t.Fatalf("jump: %+v", c)
	}
	// Mix change: 521 (connection refused) appears.
	if fire, c := UnreachableFires(bg(220, 240, 120, 16_000), base, min); !fire || !c.MixHit || c.Others != 120 {
		t.Fatalf("mix: %+v", c)
	}
	// Origin stops answering, even with the background flat.
	if fire, c := UnreachableFires(bg(220, 240, 0, 3_000), base, min); !fire || !c.CollapseHit {
		t.Fatalf("collapse: %+v", c)
	}
	// skoolopedia: 530-led trickle — never bookkeeping, the plain line rules.
	sk := Metrics{Unreachable: 18, UnreachableBy: map[string]int64{"530": 16, "522": 2}}
	skBase := Metrics{Unreachable: 15, UnreachableBy: map[string]int64{"530": 14, "522": 1}}
	if _, c := UnreachableFires(sk, skBase, min); c.Verdict != UnreachPlain {
		t.Fatalf("530 trickle judged %+v", c)
	}
	if fire, _ := UnreachableFires(Metrics{Unreachable: 40, UnreachableBy: map[string]int64{"530": 40}}, skBase, min); !fire {
		t.Fatal("plain line: 40 ≥ 10 and ≥ 2× 15 must fire")
	}
	// A normally-zero VPS origin: 522 from zero is an outage.
	if fire, c := UnreachableFires(bg(30, 0, 0, 0), Metrics{Origin: &OriginMetrics{Requests: 5_000}}, min); !fire || c.Verdict != UnreachPlain {
		t.Fatalf("VPS outage: %+v", c)
	}
	// Evaluate uses the same judgement.
	th := Thresholds{UnreachableMin: min, CollapseDownPct: 90}
	if fs := Evaluate(bg(222, 240, 0, 17_500), base, th, Known{}); has(fs, RuleUnreachable) {
		t.Fatalf("evaluate fired on the background: %v", fs)
	}
	if fs := Evaluate(bg(900, 600, 0, 16_000), base, th, Known{}); !has(fs, RuleUnreachable) {
		t.Fatal("evaluate missed the jump")
	}
}

// Hours archived before v1.15 did not measure 52x: the median must not
// read them as zero (the tile showed "baseline 0" for that reason).
func TestMedianSkipsUnmeasured52x(t *testing.T) {
	old := Metrics{Total: 1000} // pre-v1.15: no Unreachable, no Origin
	measured := func(n522, n524 int64) Metrics {
		return Metrics{Total: 1000, Unreachable: n522 + n524, UnreachableBy: map[string]int64{"522": n522, "524": n524},
			Origin: &OriginMetrics{Requests: 17_000}}
	}
	m := Median([]Metrics{old, old, old, old, measured(200, 240), measured(240, 260), measured(220, 230)})
	if m.Unreachable != 450 || m.UnreachableBy["522"] != 220 || m.UnreachableBy["524"] != 240 {
		t.Fatalf("%d %v", m.Unreachable, m.UnreachableBy)
	}
	// A measured hour with no 52x is a real zero.
	z := Median([]Metrics{{Origin: &OriginMetrics{Requests: 1}}, {Origin: &OriginMetrics{Requests: 1}}, measured(10, 0)})
	if z.Unreachable != 0 {
		t.Fatalf("%d", z.Unreachable)
	}
}
