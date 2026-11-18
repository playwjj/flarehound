package wafkit

import (
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/waf"
)

func TestExplain(t *testing.T) {
	cases := []struct{ expr, en, zh string }{
		{`starts_with(http.request.uri.path, "/login") and not cf.client.bot`,
			`the path starts with "/login" and not a Cloudflare-verified bot (Googlebot, Bingbot …)`, `路径以 "/login" 开头，且不是 Cloudflare 已核验的爬虫（Googlebot、Bingbot 等）`},
		{`(ip.geoip.asnum in {16509 24940}) or http.user_agent contains "curl"`,
			`the network (ASN) is one of {16509, 24940} or the user agent contains "curl"`, `网络（ASN） 属于 {16509, 24940}，或UA 包含 "curl"`},
		{`ip.src in $office and http.request.uri.path ne "/health"`,
			`the client IP is one of the list $office and the path is not "/health"`, ``},
		{`not http.host contains "staging"`, `the host name does not contain "staging"`, `主机名 不包含 "staging"`},
	}
	for _, c := range cases {
		if got := Explain(c.expr, "en"); got != c.en {
			t.Errorf("en %q\n got %q\nwant %q", c.expr, got, c.en)
		}
		if c.zh != "" {
			if got := Explain(c.expr, "zh"); got != c.zh {
				t.Errorf("zh %q\n got %q\nwant %q", c.expr, got, c.zh)
			}
		}
	}
	if Explain("this is ((( not an expression", "en") == "" {
		t.Fatal("unparseable expression lost")
	}
	s := RuleSentence(map[string]any{"action": "skip", "expression": "cf.client.bot",
		"action_parameters": map[string]any{"ruleset": "current", "phases": []any{"http_ratelimit"}}}, "en")
	if !strings.Contains(s, "skipping the remaining custom rules, rate limiting") {
		t.Fatalf("skip sentence: %s", s)
	}
}

func TestSkipParams(t *testing.T) {
	ap, err := SkipParams([]string{"rules", "ratelimit", "managed", "bots", "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if ap["ruleset"] != "current" || len(ap["phases"].([]any)) != 3 || ap["products"] == nil {
		t.Fatalf("params: %v", ap)
	}
	if ap, _ := SkipParams(nil); ap["ruleset"] != "current" {
		t.Fatal("default scope is not the remaining custom rules")
	}
	if _, err := SkipParams([]string{"everything"}); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

func toRule(m map[string]any, id string) cfapi.Rule {
	r := cfapi.Rule{ID: id, Action: m["action"].(string), Expression: m["expression"].(string), Description: m["description"].(string), Enabled: true}
	if ap, ok := m["action_parameters"].(map[string]any); ok {
		r.ActionParameters = &cfapi.ActionParameters{}
		if s, ok := ap["ruleset"].(string); ok {
			r.ActionParameters.Ruleset = s
		}
	}
	return r
}

func TestRecipes(t *testing.T) {
	inputs := map[string]map[string]string{
		"allow-verified-bots":      {},
		"protect-paths":            {},
		"ratelimit-paths":          {},
		"allow-service":            {"ips": "203.0.113.10, 198.51.100.0/24", "header": "X-Hook-Key", "secret": "0123456789abcdef0123", "paths": "/webhooks/*"},
		"challenge-cloud-on-paths": {},
	}
	for _, r := range Recipes() {
		v, ok := inputs[r.Name]
		if !ok {
			t.Fatalf("recipe %s has no test input", r.Name)
		}
		b, err := r.Build(v, "free")
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		expr := b.Rule["expression"].(string)
		if _, err := waf.Parse(expr); err != nil {
			t.Fatalf("%s: expression does not parse: %v\n%s", r.Name, err, expr)
		}
		if b.Rule["action"] == "skip" && b.Rule["action_parameters"] == nil {
			t.Fatalf("%s: skip rule without action_parameters", r.Name)
		}
		if r.T(r.Title, "zh") == "" || r.T(r.Why, "en") == "" {
			t.Fatalf("%s: missing explanation", r.Name)
		}
		if (b.Rule["action"] == "managed_challenge" || b.Rule["action"] == "block") && !strings.Contains(expr, "not cf.client.bot") {
			t.Fatalf("%s: protective recipe would hit verified bots: %s", r.Name, expr)
		}
	}

	// The skip recipes are not flagged as forgeable by the audit.
	var rules []cfapi.Rule
	for i, name := range []string{"allow-verified-bots", "allow-service"} {
		rc, _ := RecipeByName(name)
		b, _ := rc.Build(inputs[name], "pro")
		rules = append(rules, toRule(b.Rule, string(rune('a'+i))))
	}
	res := waf.Audit(waf.Input{Rules: rules, Hosts: []string{"example.com"}, Now: time.Now()})
	for _, e := range res.Exemptions {
		if e.Forgeable {
			t.Fatalf("recipe skip rule flagged forgeable: %+v", e)
		}
	}

	// Bad inputs are refused with a reason.
	svc, _ := RecipeByName("allow-service")
	for _, bad := range []map[string]string{
		{},                                     // nothing to tie it to
		{"paths": "/webhooks/*"},               // path alone
		{"header": "x-key", "secret": "short"}, // guessable
		{"ips": "not-an-ip"},
	} {
		if _, err := svc.Build(bad, "pro"); err == nil {
			t.Fatalf("allow-service accepted %v", bad)
		}
	}
	rl, _ := RecipeByName("ratelimit-paths")
	if _, err := rl.Build(map[string]string{"period": "60"}, "free"); err == nil {
		t.Fatal("Free plan rate limit with a 60 s period accepted")
	}
	if _, err := rl.Build(map[string]string{"period": "60"}, "pro"); err != nil {
		t.Fatalf("Pro rate limit: %v", err)
	}
	pp, _ := RecipeByName("protect-paths")
	if _, err := pp.Build(map[string]string{"paths": "login"}, "pro"); err == nil {
		t.Fatal("path without / accepted")
	}
}

func TestBefore(t *testing.T) {
	rules := []map[string]any{{"id": "s1", "action": "skip"}, {"id": "b1", "action": "block"}}
	if Before(rules, PlaceTop) != "s1" || Before(rules, PlaceAfterSkips) != "b1" || Before(rules, PlaceEnd) != "" {
		t.Fatal("placement")
	}
	rules = append(rules, map[string]any{"id": "c1", "action": "managed_challenge"})
	if Before(rules, PlaceAfterBlocks) != "c1" || Before(rules[:2], PlaceAfterBlocks) != "" {
		t.Fatal("challenges go after skips and blocks")
	}
	pp, _ := RecipeByName("protect-paths")
	if b, _ := pp.Build(nil, "pro"); b.Place != PlaceAfterBlocks {
		t.Fatalf("challenge recipe placed %s", b.Place)
	}
	if b, _ := pp.Build(map[string]string{"action": "block"}, "pro"); b.Place != PlaceAfterSkips {
		t.Fatalf("block recipe placed %s", b.Place)
	}
	if Before([]map[string]any{{"id": "s1", "action": "skip"}}, PlaceAfterSkips) != "" {
		t.Fatal("after skips with only skips should append")
	}
}

func TestFixes(t *testing.T) {
	ua := cfapi.Rule{ID: "u", Action: "skip", Expression: `http.user_agent contains "Googlebot"`, Description: "let google in", Enabled: true,
		ActionParameters: &cfapi.ActionParameters{Ruleset: "current"}}
	res := waf.Audit(waf.Input{Rules: []cfapi.Rule{ua}, Hosts: []string{"example.com"},
		Sensitive: []waf.Path{{Name: "login", Pattern: "/login*"}}, Now: time.Now()})
	fs := Fixes(res, "en")
	var recipes []string
	for _, f := range fs {
		recipes = append(recipes, f.Recipe)
	}
	got := strings.Join(recipes, ",")
	if !strings.Contains(got, "protect-paths") || !strings.Contains(got, "allow-service") {
		t.Fatalf("fixes: %+v", fs)
	}
	if fs[0].Inputs.Get("paths") != "/login*" {
		t.Fatalf("protect-paths inputs: %v", fs[0].Inputs)
	}
}

func TestFreePlan(t *testing.T) {
	r, _ := RecipeByName("allow-verified-bots")
	var skip Param
	for _, p := range r.Params {
		if p.Name == "skip" {
			skip = p
		}
	}
	for _, c := range skip.ChoicesFor("free") {
		if strings.Contains(c, "bots") {
			t.Fatalf("Free choices include %q", c)
		}
	}
	if len(skip.ChoicesFor("pro")) != len(skip.Choices) {
		t.Fatal("Pro choices filtered")
	}
	if _, err := r.Build(map[string]string{"skip": "rules,bots"}, "free"); err == nil {
		t.Fatal("Free plan skip of Super Bot Fight Mode accepted")
	}
	if _, err := r.Build(map[string]string{"skip": "rules,bots"}, "pro"); err != nil {
		t.Fatalf("Pro: %v", err)
	}
	if got := PaidScopes([]string{"rules", "Managed", "bots"}); len(got) != 2 {
		t.Fatalf("paid scopes: %v", got)
	}
}

func TestCover(t *testing.T) {
	rules := []RuleLite{
		{Action: "block", Enabled: true, Desc: "probes", Expr: `(http.host in {"example.com" "www.example.com"}) and (lower(http.request.uri.path) contains "wp-login")`},
		{Action: "block", Enabled: true, Desc: "fh asn", Expr: `(ip.geoip.asnum in {150436 207990}) and not cf.client.bot`},
		{Action: "block", Enabled: true, Desc: "ahrefs", Expr: `(http.host in {"example.com"}) and (lower(http.user_agent) contains "ahrefsbot")`},
		{Action: "managed_challenge", Enabled: false, Desc: "off", Expr: `ip.geoip.asnum in {4134}`},
		{Action: "skip", Enabled: true, Desc: "monitor", Expr: `ip.geoip.asnum in {13335}`},
	}
	if c, ok := Cover(rules, "asn", "AS150436", "example.com"); !ok || c.Pos != 2 || c.Partial {
		t.Fatalf("ASN in a block rule: %+v %v", c, ok)
	}
	if c, ok := Cover(rules, "asn", "150436", "example.com"); !ok || c.Pos != 2 {
		t.Fatalf("bare-number ASN: %+v", c)
	}
	if c, ok := Cover(rules, "ua", "Mozilla/5.0 (compatible; AhrefsBot/7.0)", "example.com"); !ok || c.Pos != 3 || c.Partial {
		t.Fatalf("UA rule: %+v %v", c, ok)
	}
	if _, ok := Cover(rules, "asn", "AS4134", "example.com"); ok {
		t.Fatal("disabled rule counted")
	}
	if c, ok := Cover(rules, "asn", "AS13335", "example.com"); !ok || c.Action != "skip" || c.Pos != 5 {
		t.Fatalf("skip rule: %+v", c)
	}
	// A rule that does not look at the face's dimension says nothing.
	if c, ok := Cover(rules[:1], "ua", "curl/8", "example.com"); ok {
		t.Fatalf("path-only rule counted: %+v", c)
	}
	// One that looks at it but also depends on the path: partial.
	pr := []RuleLite{{Action: "block", Enabled: true, Expr: `http.user_agent contains "curl" and http.request.uri.path eq "/api"`}}
	if c, ok := Cover(pr, "ua", "curl/8", "example.com"); !ok || !c.Partial {
		t.Fatalf("UA + path rule: %+v %v", c, ok)
	}
}
