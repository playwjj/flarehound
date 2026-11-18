package console

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/waf"
)

// fakeRules is an in-memory ruleset API for the execution module.
type fakeRules struct {
	mu      sync.Mutex
	rules   map[string][]map[string]any
	version int
	seq     int
}

func newFakeRules() *fakeRules {
	return &fakeRules{rules: map[string][]map[string]any{cfapi.PhaseCustom: {
		{"id": "r1", "action": "skip", "expression": `http.user_agent contains "Googlebot"`, "description": "let google in", "enabled": true,
			"action_parameters": map[string]any{"ruleset": "current"}},
		{"id": "r2", "action": "block", "expression": `ip.geoip.asnum in {207990}`, "description": "bad network", "enabled": true},
	}}, version: 1}
}

func cp(rs []map[string]any) []map[string]any {
	out := make([]map[string]any, len(rs))
	for i, r := range rs {
		m := map[string]any{}
		for k, v := range r {
			m[k] = v
		}
		out[i] = m
	}
	return out
}

func (f *fakeRules) raw(phase string) cfapi.RawRuleset {
	return cfapi.RawRuleset{ID: "rs-" + phase, Version: fmt.Sprint(f.version), Rules: cp(f.rules[phase])}
}
func (f *fakeRules) ZonePlan(context.Context, string) (string, error) { return "pro", nil }
func (f *fakeRules) PhaseRuleset(_ context.Context, _, phase string) (cfapi.RawRuleset, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.rules[phase]
	return f.raw(phase), ok, nil
}
func (f *fakeRules) PutPhaseRules(_ context.Context, _, phase string, rules []map[string]any) (cfapi.RawRuleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[phase] = cp(rules)
	for _, r := range f.rules[phase] {
		if r["id"] == nil {
			f.seq++
			r["id"] = fmt.Sprintf("n%d", f.seq)
		}
	}
	f.version++
	return f.raw(phase), nil
}
func (f *fakeRules) phaseOf(rsID string) string { return strings.TrimPrefix(rsID, "rs-") }
func (f *fakeRules) place(phase string, rule map[string]any, pos map[string]any) {
	rs := f.rules[phase]
	if pos != nil {
		for i, r := range rs {
			if r["id"] == pos["before"] {
				rs = append(rs[:i], append([]map[string]any{rule}, rs[i:]...)...)
				f.rules[phase] = rs
				return
			}
		}
	}
	f.rules[phase] = append(rs, rule)
}
func (f *fakeRules) AddRuleRaw(_ context.Context, _, rsID string, rule, pos map[string]any) (cfapi.RawRuleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ph := f.phaseOf(rsID)
	r := cp([]map[string]any{rule})[0]
	f.seq++
	r["id"] = fmt.Sprintf("n%d", f.seq)
	f.place(ph, r, pos)
	f.version++
	return f.raw(ph), nil
}
func (f *fakeRules) UpdateRuleRaw(_ context.Context, _, rsID, id string, rule, pos map[string]any) (cfapi.RawRuleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ph := f.phaseOf(rsID)
	rs := f.rules[ph]
	for i, r := range rs {
		if r["id"] == id {
			nr := cp([]map[string]any{rule})[0]
			nr["id"] = id
			if pos == nil {
				rs[i] = nr
			} else {
				f.rules[ph] = append(rs[:i:i], rs[i+1:]...)
				f.place(ph, nr, pos)
			}
			f.version++
			return f.raw(ph), nil
		}
	}
	return cfapi.RawRuleset{}, fmt.Errorf("no rule %s", id)
}
func (f *fakeRules) DeleteRuleRaw(_ context.Context, _, rsID, id string) (cfapi.RawRuleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ph := f.phaseOf(rsID)
	rs := f.rules[ph]
	for i, r := range rs {
		if r["id"] == id {
			f.rules[ph] = append(rs[:i:i], rs[i+1:]...)
			f.version++
			return f.raw(ph), nil
		}
	}
	return cfapi.RawRuleset{}, fmt.Errorf("no rule %s", id)
}
func (f *fakeRules) custom() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cp(f.rules[cfapi.PhaseCustom])
}

func rulesEnv(t *testing.T, write bool) (*writeEnv, *fakeRules) {
	e := newWriteEnv(t, false)
	fr := newFakeRules()
	e.srv.RulesRead, e.srv.Store = fr, e.st
	if write {
		e.srv.RulesWrite = fr
	}
	return e, fr
}

// reviewRule posts a review and returns the page and the apply form.
func reviewRule(t *testing.T, c *client, form url.Values) (string, url.Values) {
	t.Helper()
	_, body, _ := c.do("GET", "/rules", nil, nil)
	form.Set("csrf", csrfOf(t, body))
	code, body, _ := c.do("POST", "/rules/review", form, nil)
	if code != http.StatusOK {
		t.Fatalf("review: %d\n%s", code, body)
	}
	apply := url.Values{}
	for k, v := range form {
		apply[k] = v
	}
	m := reviewRE.FindStringSubmatch(body)
	if m == nil {
		return body, nil
	}
	apply.Set("review", m[1])
	apply.Set("csrf", csrfOf(t, body))
	if v := regexpVersion.FindStringSubmatch(body); v != nil {
		apply.Set("version", v[1])
	}
	return body, apply
}

func TestRulesPage(t *testing.T) {
	e, fr := rulesEnv(t, true)
	c := e.admin
	_, body, _ := c.do("GET", "/rules", nil, nil)
	for _, want := range []string{"the user agent contains", "the network (ASN) is one of {207990}", "Add a rule from a recipe"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rules page lacks %q", want)
		}
	}

	// Recipe: protect paths, placed after the skip rule.
	if code, _, _ := c.do("GET", "/rules/recipe/protect-paths?paths=%2Flogin*", nil, nil); code != http.StatusOK {
		t.Fatalf("recipe form: %d", code)
	}
	form := url.Values{"op": {"recipe"}, "recipe": {"protect-paths"}, "in_paths": {"/login*"}, "in_action": {"managed_challenge"}}
	body, apply := reviewRule(t, c, form)
	if apply == nil || !strings.Contains(body, "If the path starts with") {
		t.Fatalf("recipe review:\n%s", body)
	}
	// Tampering with the reviewed inputs is refused.
	bad := url.Values{}
	for k, v := range apply {
		bad[k] = v
	}
	bad.Set("in_paths", "/*")
	if code, _, _ := c.do("POST", "/rules/apply", bad, nil); code != http.StatusBadRequest {
		t.Fatalf("tampered recipe applied: %d", code)
	}
	if code, _, h := c.do("POST", "/rules/apply", apply, nil); code != http.StatusSeeOther {
		t.Fatalf("apply: %d %s", code, h.Get("Location"))
	}
	rs := fr.custom()
	if len(rs) != 3 || rs[0]["id"] != "r1" || rs[1]["id"] != "r2" || rs[2]["action"] != "managed_challenge" {
		t.Fatalf("challenge recipe not placed after the skip and block rules: %v", rs)
	}
	if bs, _ := e.st.RuleBackups(zoneID, "", 10); len(bs) != 1 {
		t.Fatalf("no backup before the change: %d", len(bs))
	}

	// A change made by someone else between review and apply: review again.
	newID := rs[2]["id"].(string)
	_, apply = reviewRule(t, c, url.Values{"op": {"disable"}, "sel": {newID}, "phase": {"custom"}})
	fr.mu.Lock()
	fr.version++
	fr.mu.Unlock()
	if _, body, _ := c.do("POST", "/rules/apply", apply, nil); !strings.Contains(body, "rules changed since this review") {
		t.Fatal("stale review applied")
	}
	if fr.custom()[2]["enabled"] != true {
		t.Fatal("rule changed despite a stale review")
	}
	_, apply = reviewRule(t, c, url.Values{"op": {"disable"}, "sel": {newID}, "phase": {"custom"}})
	if code, _, _ := c.do("POST", "/rules/apply", apply, nil); code != http.StatusSeeOther || fr.custom()[2]["enabled"] != false {
		t.Fatalf("disable: %d %v", code, fr.custom()[2])
	}

	// Move the block rule to the top.
	_, apply = reviewRule(t, c, url.Values{"op": {"top"}, "sel": {"r2"}, "phase": {"custom"}})
	if code, _, _ := c.do("POST", "/rules/apply", apply, nil); code != http.StatusSeeOther || fr.custom()[0]["id"] != "r2" {
		t.Fatalf("move to top: %d %v", code, fr.custom())
	}

	// Restore the first backup: back to the original two rules.
	bs, _ := e.st.RuleBackups(zoneID, "", 10)
	first := bs[len(bs)-1].ID
	_, apply = reviewRule(t, c, url.Values{"op": {"restore"}, "sel": {fmt.Sprint(first)}, "phase": {"custom"}})
	if code, _, _ := c.do("POST", "/rules/apply", apply, nil); code != http.StatusSeeOther {
		t.Fatalf("restore: %d", code)
	}
	if rs := fr.custom(); len(rs) != 2 || rs[0]["id"] != "r1" {
		t.Fatalf("restore result: %v", rs)
	}
	log, _ := e.db.AuditLog(50)
	applied := 0
	for _, l := range log {
		if l.Action == "rule_applied" {
			applied++
		}
	}
	if applied != 4 {
		t.Fatalf("console audit: %d rule_applied entries", applied)
	}

	// Viewers read, never change.
	v := e.login(t, "viewer", "viewer-password-1")
	if _, body, _ := v.do("GET", "/rules", nil, nil); strings.Contains(body, `action="/rules/review"`) {
		t.Fatal("viewer sees rule actions")
	}
	if code, _, _ := v.do("GET", "/rules/recipe/protect-paths", nil, nil); code != http.StatusForbidden {
		t.Fatalf("viewer recipe form: %d", code)
	}
}

func TestRulesReadOnlyAndAuditFixes(t *testing.T) {
	e, _ := rulesEnv(t, false)
	e.srv.Auditor = func(_ context.Context, z config.Zone) (report.AuditData, error) {
		ua := cfapi.Rule{ID: "u", Action: "skip", Expression: `http.user_agent contains "Googlebot"`, Description: "let google in", Enabled: true,
			ActionParameters: &cfapi.ActionParameters{Ruleset: "current"}}
		res := waf.Audit(waf.Input{Rules: []cfapi.Rule{ua}, Hosts: []string{z.Name}, Sensitive: []waf.Path{{Name: "login", Pattern: "/login*"}}})
		return report.AuditData{Zone: z.Name, Result: res}, nil
	}
	c := e.admin
	_, body, _ := c.do("GET", "/rules", nil, nil)
	if !strings.Contains(body, "let google in") || strings.Contains(body, `action="/rules/review"`) {
		t.Fatal("read-only console: list missing or actions offered")
	}
	if code, _, _ := c.do("GET", "/rules/recipe/protect-paths", nil, nil); code != http.StatusForbidden {
		t.Fatalf("read-only recipe form: %d", code)
	}
	_, body, _ = c.do("GET", "/audit", nil, nil)
	if !strings.Contains(body, "How to fix") || !strings.Contains(body, "flarehound rules recipe protect-paths") {
		t.Fatalf("audit page lacks fixes:\n%s", body)
	}
	if _, body, _ := c.do("GET", "/rules/recipes", nil, nil); !strings.Contains(body, "Let verified search-engine bots through") {
		t.Fatal("recipe catalogue missing")
	}
}

var regexpVersion = regexp.MustCompile(`name="version" value="([^"]*)"`)
