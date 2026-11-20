package purpose

import (
	"math"
	"testing"
)

const chrome157 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"

func TestBuiltinTableLoads(t *testing.T) {
	tab := New(nil)
	if !tab.OK() {
		t.Fatalf("built-in table: %v", tab.Err())
	}
	if tab.Version() == "" || tab.Size() < 20 {
		t.Fatalf("version %q, %d entries", tab.Version(), tab.Size())
	}
}

// The proposal's named samples.
func TestNamedSamples(t *testing.T) {
	tab := New(nil)
	cases := map[string]Class{
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)":           Training,
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot": Search,
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot":        UserAction,
		"ExaSearchBot/1.0": Tool,
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": Mixed,
		"rednote-websearch-bot/1.0":                                         Tool,
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)": Training,
		"Claude-SearchBot/1.0":                                              Search,
		"Claude-User/1.0":                                                   UserAction,
		"Perplexity-User/1.0":                                               UserAction,
		"PerplexityBot/1.0":                                                 Search,
		"meta-externalagent/1.1":                                            Training,
		"meta-externalfetcher/1.1":                                          UserAction,
		"Mozilla/5.0 (compatible; Applebot/0.1)":                            Search,
	}
	for ua, want := range cases {
		lb, ok := tab.Named(ua)
		if !ok || lb.Class != want {
			t.Errorf("%q: got %v %v, want %s", ua, lb, ok, want)
		}
		if ok && lb.Trust != Claimed {
			t.Errorf("%q: a name alone is self-declared, got %s", ua, lb.Trust)
		}
	}
	for _, ua := range []string{chrome157, "curl/8.0", "", "Mozilla/5.0 (compatible; AhrefsBot/7.0)"} {
		if lb, ok := tab.Named(ua); ok {
			t.Errorf("%q: untagged expected, got %v", ua, lb)
		}
	}
}

func TestVerifiedAndSelfDeclared(t *testing.T) {
	tab := New(nil)
	o := Options{HasASN: true, HasBot: true}
	lb, _ := tab.Classify("ClaudeBot/1.0", []Row{{UA: "ClaudeBot/1.0", ASN: 16509, Verified: true, Count: 100}}, o)
	if lb.Class != Training || lb.Trust != Verified {
		t.Fatalf("verified ClaudeBot: %+v", lb)
	}
	lb, _ = tab.Classify("rednote-websearch-bot", []Row{{UA: "rednote-websearch-bot", ASN: 45102, Count: 100}}, o)
	if lb.Class != Tool || lb.Trust != Claimed {
		t.Fatalf("rednote: %+v", lb)
	}
	// Without the verified-bot dimension nothing can be verified.
	lb, _ = tab.Classify("ClaudeBot/1.0", []Row{{UA: "ClaudeBot/1.0", Verified: true, Count: 100}}, Options{})
	if lb.Trust != Claimed {
		t.Fatalf("no bot dimension: %+v", lb)
	}
}

func hosting(asn int) bool { return asn == 45102 || asn == 16509 }

// AS45102's slice as measured on 2026-11-20: the Chrome/157 family from
// Alibaba Cloud, rednote, other browser UAs from the same network.
func TestFacet45102(t *testing.T) {
	tab := New(nil)
	rows := []Row{
		{UA: chrome157, ASN: 45102, Count: 514057},
		{UA: "rednote-websearch-bot/1.0", ASN: 45102, Count: 7598},
		{UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", ASN: 45102, Count: 60000},
		{UA: "python-requests/2.31", ASN: 45102, Count: 1000},
	}
	var total int64
	for _, r := range rows {
		total += r.Count
	}
	f := tab.Facet(rows, Options{HasASN: true, HasBot: true, Hosting: hosting})
	und := 100 * float64(f.Count(Undeclared)) / float64(total)
	tool := 100 * float64(f.Count(Tool)) / float64(total)
	if und < 97 || und > 99 {
		t.Errorf("undeclared %.1f%%, want ≈98%%", und)
	}
	if math.Abs(tool-1.3) > 0.1 {
		t.Errorf("tool %.2f%%, want ≈1.3%%", tool)
	}
	if f.Count(Training) != 0 || f.Count(UserAction) != 0 {
		t.Errorf("training %d, user action %d: want 0", f.Count(Training), f.Count(UserAction))
	}
	top := f.Stats[Undeclared].Actors[0]
	if top.UA != chrome157 || !top.Traits[TraitHosting] || top.Trust(Undeclared, true) != Behaviour {
		t.Errorf("top undeclared actor: %+v", top)
	}
	if asn, n := top.TopASN(); asn != 45102 || n != 514057 {
		t.Errorf("top ASN %d %d", asn, n)
	}
}

// A browser UA from an eyeball network is not undeclared automation;
// without the ASN dimension undeclared is not judged at all.
func TestUndeclaredNeedsTraits(t *testing.T) {
	tab := New(nil)
	rows := []Row{{UA: chrome157, ASN: 22773, Count: 100}}
	if f := tab.Facet(rows, Options{HasASN: true, Hosting: hosting}); f.Count(Undeclared) != 0 {
		t.Error("eyeball network counted as undeclared")
	}
	if f := tab.Facet([]Row{{UA: chrome157, Count: 100}}, Options{Hosting: hosting}); f.Count(Undeclared) != 0 {
		t.Error("judged undeclared without ASNs")
	}
	headless := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"
	if f := tab.Facet([]Row{{UA: headless, Count: 5}}, Options{}); f.Count(Undeclared) != 5 {
		t.Error("headless browser not undeclared")
	}
}

func TestOverrides(t *testing.T) {
	tab := New(map[string]string{"rednote": "search", "GPTBot": "none", "MyFetcher": "tool", "bad": "nonsense"})
	if tab.Overrides() != 3 {
		t.Fatalf("overrides %d", tab.Overrides())
	}
	if lb, _ := tab.Named("rednote-websearch-bot/1.0"); lb.Class != Search || !lb.Override || lb.Operator != "Xiaohongshu" {
		t.Errorf("re-filed rednote: %+v", lb)
	}
	if _, ok := tab.Named("GPTBot/1.2"); ok {
		t.Error("none override still tagged")
	}
	if lb, _ := tab.Named("myfetcher/2"); lb.Class != Tool {
		t.Errorf("local UA: %+v", lb)
	}
	// "none" also keeps a browser UA out of undeclared.
	tab = New(map[string]string{"Chrome/157": "none"})
	if f := tab.Facet([]Row{{UA: chrome157, ASN: 45102, Count: 10}}, Options{HasASN: true, Hosting: hosting}); f.Tagged() != 0 {
		t.Error("none override did not untag")
	}
}

func TestBrokenTableIsOff(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("{"), []byte(`{"version":"x","entries":[]}`), []byte(`{"version":"x","entries":[{"match":"A","class":"weird"}]}`)} {
		tf, err := parse(raw)
		tab := build(tf, err, map[string]string{"x-agent": "tool"})
		if tab.OK() || tab.Err() == nil {
			t.Errorf("%q: table should be off", raw)
		}
		if _, ok := tab.Named("GPTBot"); ok {
			t.Error("off table labels")
		}
		if f := tab.Facet([]Row{{UA: "GPTBot", Count: 1}}, Options{}); f.Tagged() != 0 {
			t.Error("off table classifies")
		}
	}
}

func TestLongestMarkerWins(t *testing.T) {
	tab := New(nil)
	if lb, _ := tab.Named("Ai2Bot-Dolma"); lb.Name != "Ai2Bot-Dolma" {
		t.Errorf("got %+v", lb)
	}
	if lb, _ := tab.Named("FirecrawlAgent/1"); lb.Name != "FirecrawlAgent" {
		t.Errorf("got %+v", lb)
	}
}

func TestShifts(t *testing.T) {
	cur := Facet{Stats: map[Class]*Stat{Undeclared: {Count: 41}, Training: {Count: 6}}}
	base := Facet{Stats: map[Class]*Stat{Undeclared: {Count: 29}, Training: {Count: 5}}}
	s := Shifts(cur, base, 100, 100)
	if len(s) != 1 || s[0].Class != Undeclared || math.Abs(s[0].PP()-12) > 1e-9 {
		t.Fatalf("shifts %+v", s)
	}
	if Shifts(cur, base, 0, 100) != nil {
		t.Error("no total, no shift")
	}
}
