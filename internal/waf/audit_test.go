package waf

import (
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func rule(id, action, expr string) cfapi.Rule {
	return cfapi.Rule{ID: id, Action: action, Expression: expr, Description: id, Enabled: true, LastUpdated: now.AddDate(0, -3, 0)}
}

func skip(id, expr string) cfapi.Rule {
	r := rule(id, "skip", expr)
	r.ActionParameters = &cfapi.ActionParameters{Ruleset: "current"}
	return r
}

func find(res Result, kind, ruleID string) bool {
	for _, f := range res.Order {
		if f.Kind == kind && f.Rule.ID == ruleID {
			return true
		}
	}
	return false
}

func TestAudit(t *testing.T) {
	rules := []cfapi.Rule{
		skip("ua-skip", `http.user_agent contains "MyMonitor"`),                                             // forgeable exemption
		skip("office-skip", `ip.src in {198.51.100.0/24} and starts_with(http.request.uri.path, "/admin")`), // fine exemption
		rule("login", "managed_challenge", `starts_with(http.request.uri.path, "/login")`),
		rule("api-block", "block", `starts_with(http.request.uri.path, "/api")`),
		rule("api-v2", "block", `starts_with(http.request.uri.path, "/api") and http.request.method eq "POST"`), // shadowed
		rule("login-dup", "managed_challenge", `starts_with(http.request.uri.path, "/login")`),                  // duplicate
		rule("admin", "block", `starts_with(http.request.uri.path, "/admin")`),                                  // partly skipped by office-skip
		rule("bad", "block", `this is not (valid`),
	}
	rules = append(rules, rule("off", "block", "true"))
	rules[len(rules)-1].Enabled = false

	res := Audit(Input{
		Hosts: []string{"example.com"},
		Rules: rules,
		Sensitive: []Path{
			{Name: "login", Pattern: "/login*"},
			{Name: "admin", Pattern: "/admin*"},
			{Name: "search", Pattern: "/search*"},
		},
		Plan: "pro",
		Hits: map[string]Hits{"login": {D7: 50, D30: 900}, "api-block": {D30: 3}},
		Now:  now,
	})

	cov := map[string]Coverage{}
	for _, c := range res.Coverage {
		cov[c.Path.Name] = c
	}
	if c := cov["login"]; c.Status != Covered || c.By.ID != "login" || c.MaySkipBy == nil || c.MaySkipBy.ID != "ua-skip" {
		t.Errorf("login coverage %+v", c)
	}
	if c := cov["admin"]; c.Status != Covered || c.MaySkipBy == nil {
		t.Errorf("admin coverage %+v", c)
	}
	if c := cov["search"]; c.Status != Gap {
		t.Errorf("search coverage %+v", c)
	}
	if !find(res, Shadowed, "api-v2") || !find(res, Duplicate, "login-dup") || !find(res, SkipOverlap, "admin") {
		t.Errorf("order findings %+v", res.Order)
	}
	if find(res, Shadowed, "login") {
		t.Error("challenge rules do not shadow")
	}
	ex := map[string]Exemption{}
	for _, e := range res.Exemptions {
		ex[e.Rule.ID] = e
	}
	if !ex["ua-skip"].Forgeable || ex["office-skip"].Forgeable {
		t.Errorf("exemptions %+v", res.Exemptions)
	}
	if len(res.ParseErrors) != 1 || res.Disabled != 1 {
		t.Errorf("parse errors %+v disabled %d", res.ParseErrors, res.Disabled)
	}
	zombies := map[string]bool{}
	for _, z := range res.Zombies {
		zombies[z.Rule.ID] = true
	}
	if !zombies["admin"] || zombies["login"] || zombies["api-block"] || zombies["ua-skip"] {
		t.Errorf("zombies %+v", res.Zombies)
	}
	if res.Quota.Near || res.Quota.Limit != 20 {
		t.Errorf("quota %+v", res.Quota)
	}
	if res.Problems() == 0 {
		t.Error("problems not counted")
	}
}

func TestSkipFullyShadows(t *testing.T) {
	res := Audit(Input{Hosts: []string{"e.com"}, Now: now, Rules: []cfapi.Rule{
		skip("s", `starts_with(http.request.uri.path, "/api")`),
		rule("b", "block", `starts_with(http.request.uri.path, "/api") and ip.geoip.country eq "XX"`),
	}})
	if !find(res, SkipShadows, "b") {
		t.Fatalf("order %+v", res.Order)
	}
}

func TestExemptedPath(t *testing.T) {
	res := Audit(Input{Hosts: []string{"e.com"}, Now: now, Sensitive: []Path{{Name: "l", Pattern: "/login"}}, Rules: []cfapi.Rule{
		skip("s", `http.request.uri.path eq "/login"`),
		rule("b", "managed_challenge", `http.request.uri.path eq "/login"`),
	}})
	if c := res.Coverage[0]; c.Status != Exempted || c.By.ID != "s" {
		t.Fatalf("coverage %+v", c)
	}
}

// TestRealZone: the live 404401.xyz ruleset on a Free plan.
func TestRealZone(t *testing.T) {
	res := Audit(Input{
		Hosts: []string{"404401.xyz"}, Plan: "free", Now: now,
		Rules:     []cfapi.Rule{rule("wp", "block", realWP), rule("php", "block", realPHP), rule("ua", "block", realUA)},
		Sensitive: []Path{{Name: "wp-login", Pattern: "/wp-login.php"}, {Name: "login", Pattern: "/login*"}},
	})
	if len(res.ParseErrors) != 0 || len(res.Order) != 0 {
		t.Fatalf("parse %+v order %+v", res.ParseErrors, res.Order)
	}
	// /login is only touched by the AhrefsBot UA rule, which applies to
	// every path alike: that is no coverage of /login.
	if res.Coverage[0].Status != Covered || res.Coverage[0].Level != "block" || res.Coverage[1].Status != Gap {
		t.Fatalf("coverage %+v", res.Coverage)
	}
	if !res.HitsNA || len(res.Zombies) != 0 {
		t.Fatal("no hit data must mean no zombie claims")
	}
	if res.Quota.Near || res.Quota.Used != 3 || res.Quota.Limit != 5 {
		t.Fatalf("quota %+v", res.Quota)
	}
	// One more rule (4 of 5) crosses the 80% line: merge advice appears.
	res = Audit(Input{Hosts: []string{"404401.xyz"}, Plan: "free", Now: now,
		Rules: []cfapi.Rule{rule("wp", "block", realWP), rule("php", "block", realPHP), rule("ua", "block", realUA),
			rule("x", "managed_challenge", `http.request.uri.path eq "/x"`)}})
	if !res.Quota.Near || len(res.Quota.Mergeable) != 1 || len(res.Quota.Mergeable[0]) != 3 {
		t.Fatalf("quota %+v", res.Quota)
	}
}

// TestCoverageLevels: an unconditional Managed Challenge on a path (with
// "and not cf.client.bot") is full coverage at challenge level, not
// "partial"; general rules (IP list, crawler UA) are not path coverage.
func TestCoverageLevels(t *testing.T) {
	res := Audit(Input{Hosts: []string{"e.com"}, Now: now, Sensitive: []Path{{Name: "ff", Pattern: "/fake-follower*"}, {Name: "api", Pattern: "/v1/x/*"}}, Rules: []cfapi.Rule{
		rule("iplist", "block", `ip.src in $blocked`),
		rule("ua", "block", `http.user_agent contains "GPTBot" and http.request.uri.path ne "/robots.txt"`),
		rule("pages", "managed_challenge", `(http.request.uri.path contains "/fake-follower") and not cf.client.bot`),
	}})
	ff, api := res.Coverage[0], res.Coverage[1]
	if ff.Status != Covered || ff.Level != "challenge" || ff.By.ID != "pages" || ff.BlockStatus != Gap {
		t.Fatalf("fake-follower %+v", ff)
	}
	if api.Status != Gap || api.BlockStatus != Gap {
		t.Fatalf("general rules counted as path coverage: %+v", api)
	}
}
