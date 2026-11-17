package suggest

import (
	"testing"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
)

func surge() Input {
	return Input{
		Base: analyze.Metrics{Total: 100_000, Dynamic: 40_000,
			TopASN: []cfapi.Face{{Name: "AS4134", ASN: 4134, Count: 50_000}}},
		Cur: analyze.Metrics{Total: 150_000, Dynamic: 70_000,
			TopASN: []cfapi.Face{{Name: "AS4134", ASN: 4134, Count: 50_000}, {Name: "AS24940", ASN: 24940, Count: 45_000}}},
		Hypotheses: []analyze.Hypothesis{{ID: analyze.HypNewFaceSurge, Confidence: analyze.High}},
		MinCount:   1000,
	}
}

func kinds(ss []Suggestion) map[Kind]Suggestion {
	m := map[Kind]Suggestion{}
	for _, s := range ss {
		m[s.Kind] = s
	}
	return m
}

func TestHostingASNIsBlocked(t *testing.T) {
	got := kinds(Suggest(surge()))
	s, ok := got[BlockASN]
	if !ok || s.ASN != 24940 || s.Expression != "(ip.geoip.asnum in {24940}) and not cf.client.bot" {
		t.Fatalf("got %+v", got)
	}
	if s.GainRequests != 45_000 || s.GainExpensive <= 0 || s.GainExpensive > 45_000 {
		t.Fatalf("gain %+v", s)
	}
}

func TestEyeballASNIsOnlyChallenged(t *testing.T) {
	in := surge()
	in.Cur.TopASN[1] = cfapi.Face{Name: "AS4837", ASN: 4837, Count: 45_000}
	got := kinds(Suggest(in))
	if _, blocked := got[BlockASN]; blocked {
		t.Fatal("backbone/eyeball ASN must never be suggested for blocking")
	}
	if got[ChallengeASN].ASN != 4837 {
		t.Fatalf("got %+v", got)
	}
}

func TestUnknownASNIsOnlyChallenged(t *testing.T) {
	in := surge()
	in.Cur.TopASN[1] = cfapi.Face{Name: "AS64512", ASN: 64512, Count: 45_000}
	if _, blocked := kinds(Suggest(in))[BlockASN]; blocked {
		t.Fatal("unknown network must default to challenge")
	}
	in.ASNNames = map[int]string{64512: "EXAMPLE-VPS-HOSTING"}
	if _, blocked := kinds(Suggest(in))[BlockASN]; !blocked {
		t.Fatal("hosting name should classify as hosting")
	}
}

func TestNoEvidenceNoAction(t *testing.T) {
	in := surge()
	in.Hypotheses = []analyze.Hypothesis{{ID: analyze.HypDiffuse, Confidence: analyze.Low}}
	for _, s := range Suggest(in) {
		if s.Kind == BlockASN || s.Kind == ChallengeASN || s.Kind == RateLimit || s.Kind == ChallengePath {
			t.Fatalf("low-confidence round produced %+v", s)
		}
	}
}

func TestCheapVolumeNoAction(t *testing.T) {
	in := surge()
	in.Hypotheses = append(in.Hypotheses, analyze.Hypothesis{ID: analyze.HypCheapVolume, Confidence: analyze.High})
	if ss := Suggest(in); len(ss) != 0 {
		t.Fatalf("cheap edge volume must not trigger blocking: %+v", ss)
	}
}

func TestSensitivePathChallenge(t *testing.T) {
	in := surge()
	in.Sensitive = map[string]string{"login": "/login*"}
	in.Attr.DynamicPaths = []analyze.PathDelta{{Path: "/login/submit", Cur: 25_000, Base: 1_000}}
	s, ok := kinds(Suggest(in))[ChallengePath]
	if !ok || s.Target != "/login*" || s.Expression != `starts_with(http.request.uri.path, "/login")` {
		t.Fatalf("got %+v", s)
	}
	// A path rule finding alone is enough.
	in.Attr.DynamicPaths = nil
	in.Findings = []analyze.Finding{{Rule: analyze.RulePathUp, Subject: "login", Cur: 300, Base: 10}}
	if _, ok := kinds(Suggest(in))[ChallengePath]; !ok {
		t.Fatal("path rule finding did not produce a challenge")
	}
}

func TestRateLimitNeedsDispersedSources(t *testing.T) {
	in := surge()
	in.Attr.DynamicPaths = []analyze.PathDelta{{Path: "/rank", Cur: 35_000, Base: 10_000}}
	if _, ok := kinds(Suggest(in))[RateLimit]; ok {
		t.Fatal("rate limit without knowing sources are dispersed")
	}
	in.Block = analyze.BlockAdvice{Dispersed: true}
	s, ok := kinds(Suggest(in))[RateLimit]
	if !ok || s.RLRequests != 20 || s.RLPeriodSec != 10 {
		t.Fatalf("got %+v", s)
	}
	in.Block = analyze.BlockAdvice{Candidates: []analyze.IPShare{{IP: "203.0.113.7"}}}
	if _, ok := kinds(Suggest(in))[RateLimit]; ok {
		t.Fatal("concentrated source: block the IP, not rate-limit the path")
	}
}

func TestCacheOpportunity(t *testing.T) {
	ss := CacheOpportunities([]analyze.PathDelta{
		{Path: "/assets/app.3f2a.js", Cur: 8000},
		{Path: "/api/data.json", Cur: 9000},
		{Path: "/logo.png", Cur: 10},
		{Path: "/rank", Cur: 50_000},
	}, 1000)
	if len(ss) != 1 || ss[0].Target != "/assets/app.3f2a.js" {
		t.Fatalf("got %+v", ss)
	}
}

func TestCostHint(t *testing.T) {
	in := Input{
		Cur:        analyze.Metrics{Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 5000, CPUP50ms: 9}}},
		Base:       analyze.Metrics{Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 5000, CPUP50ms: 6}}},
		Hypotheses: []analyze.Hypothesis{{ID: analyze.HypSlowPath, Confidence: analyze.Medium, Subject: "web"}},
	}
	s, ok := kinds(Suggest(in))[CostHint]
	if !ok || s.Target != "web" || s.CPUPct != 50 {
		t.Fatalf("got %+v", s)
	}
}

func TestExpressions(t *testing.T) {
	cases := map[string]string{
		"/login":    `http.request.uri.path eq "/login"`,
		"/login*":   `starts_with(http.request.uri.path, "/login")`,
		"/u/*/edit": `http.request.uri.path wildcard "/u/*/edit"`,
		`/a"b\c`:    `http.request.uri.path eq "/a\"b\\c"`,
	}
	for in, want := range cases {
		if got := PathExpression(in); got != want {
			t.Errorf("PathExpression(%q) = %s, want %s", in, got, want)
		}
	}
	if !Match("/login*", "/login/x") || Match("/login*", "/admin/login") || !Match("/u/*/edit", "/u/42/edit") {
		t.Error("Match")
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		asn  int
		name string
		want Network
	}{
		{16509, "", Hosting}, {4134, "", Eyeball}, {1, "", Unknown},
		{2, "COMCAST-7922", Eyeball}, {3, "Colombia Movil", Eyeball}, {4, "Some Cloud Hosting Ltd", Hosting}, {150436, "", Hosting}, {5, "Byteplus Pte. Ltd.", Hosting},
	} {
		if got := Classify(c.asn, c.name); got != c.want {
			t.Errorf("Classify(%d,%q) = %s, want %s", c.asn, c.name, got, c.want)
		}
	}
}
