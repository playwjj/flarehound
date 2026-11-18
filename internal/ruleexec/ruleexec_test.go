package ruleexec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/store"
)

type fakeCF struct {
	plan    string
	phases  map[string]*cfapi.RawRuleset
	seq     int
	denied  map[string]bool
	corrupt bool // simulate a server that silently changes the expression
}

func newFake() *fakeCF {
	return &fakeCF{plan: "free", phases: map[string]*cfapi.RawRuleset{}, denied: map[string]bool{}}
}

func (f *fakeCF) id() string { f.seq++; return fmt.Sprintf("id%d", f.seq) }

func (f *fakeCF) seed(phase string, rules ...map[string]any) {
	rs := &cfapi.RawRuleset{ID: "rs-" + phase, Version: "1"}
	for _, r := range rules {
		r = clone(r)
		r["id"] = f.id()
		if r["ref"] == nil {
			r["ref"] = r["id"]
		}
		rs.Rules = append(rs.Rules, r)
	}
	f.phases[phase] = rs
}

func (f *fakeCF) snapshot(phase string) cfapi.RawRuleset {
	rs := f.phases[phase]
	out := cfapi.RawRuleset{ID: rs.ID, Version: rs.Version}
	for _, r := range rs.Rules {
		out.Rules = append(out.Rules, clone(r))
	}
	return out
}

func (f *fakeCF) bump(phase string) {
	rs := f.phases[phase]
	var v int
	fmt.Sscan(rs.Version, &v)
	rs.Version = fmt.Sprint(v + 1)
}

func (f *fakeCF) ZonePlan(context.Context, string) (string, error) { return f.plan, nil }
func (f *fakeCF) PhaseRuleset(_ context.Context, _, phase string) (cfapi.RawRuleset, bool, error) {
	if f.denied[phase] {
		return cfapi.RawRuleset{}, false, &cfapi.APIError{Status: 403, Message: "request is not authorized"}
	}
	if _, ok := f.phases[phase]; !ok {
		return cfapi.RawRuleset{}, false, nil
	}
	return f.snapshot(phase), true, nil
}
func (f *fakeCF) PutPhaseRules(_ context.Context, _, phase string, rules []map[string]any) (cfapi.RawRuleset, error) {
	old := f.phases[phase]
	f.seed(phase, rules...)
	if old != nil {
		f.phases[phase].Version = old.Version
		f.bump(phase)
	}
	return f.snapshot(phase), nil
}
func (f *fakeCF) index(phase, id string) int {
	return slices.IndexFunc(f.phases[phase].Rules, func(r map[string]any) bool { return r["id"] == id })
}
func (f *fakeCF) phaseOf(rsID string) string { return strings.TrimPrefix(rsID, "rs-") }
func (f *fakeCF) place(phase string, r map[string]any, pos map[string]any) {
	rules := f.phases[phase].Rules
	at := len(rules)
	if b, ok := pos["before"].(string); ok {
		at = f.index(phase, b)
	} else if a, ok := pos["after"].(string); ok {
		at = f.index(phase, a) + 1
	}
	f.phases[phase].Rules = slices.Insert(rules, at, r)
}
func (f *fakeCF) AddRuleRaw(_ context.Context, _, rsID string, rule, pos map[string]any) (cfapi.RawRuleset, error) {
	phase := f.phaseOf(rsID)
	if phase == cfapi.PhaseRateLimit && len(f.phases[phase].Rules) >= 1 {
		return cfapi.RawRuleset{}, &cfapi.APIError{Status: 400, Message: "exceeded maximum number of rules"}
	}
	r := clone(rule)
	r["id"] = f.id()
	if f.corrupt {
		r["expression"] = "true"
	}
	f.place(phase, r, pos)
	f.bump(phase)
	return f.snapshot(phase), nil
}
func (f *fakeCF) UpdateRuleRaw(_ context.Context, _, rsID, ruleID string, rule, pos map[string]any) (cfapi.RawRuleset, error) {
	phase := f.phaseOf(rsID)
	i := f.index(phase, ruleID)
	r := clone(rule)
	r["id"] = ruleID
	f.phases[phase].Rules = slices.Delete(f.phases[phase].Rules, i, i+1)
	if pos == nil {
		f.phases[phase].Rules = slices.Insert(f.phases[phase].Rules, i, r)
	} else {
		f.place(phase, r, pos)
	}
	f.bump(phase)
	return f.snapshot(phase), nil
}
func (f *fakeCF) DeleteRuleRaw(_ context.Context, _, rsID, ruleID string) (cfapi.RawRuleset, error) {
	phase := f.phaseOf(rsID)
	i := f.index(phase, ruleID)
	f.phases[phase].Rules = slices.Delete(f.phases[phase].Rules, i, i+1)
	f.bump(phase)
	return f.snapshot(phase), nil
}

func setup(t *testing.T) (*Executor, *fakeCF) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := newFake()
	f.seed(cfapi.PhaseCustom,
		map[string]any{"description": "Block WP probes", "action": "block", "enabled": true, "expression": `http.request.uri.path contains "wp-"`},
		map[string]any{"description": "skip monitors", "action": "skip", "enabled": true, "expression": `ip.src in {198.51.100.0/24}`,
			"action_parameters": map[string]any{"ruleset": "current"}, "logging": map[string]any{"enabled": true}},
		map[string]any{"description": "flarehound-asn-challenge (managed by FlareHound)", "ref": "flarehound-asn-challenge",
			"action": "managed_challenge", "enabled": true, "expression": "(ip.geoip.asnum in {64496}) and not cf.client.bot"},
	)
	x := &Executor{API: f, Store: st, ZoneID: "z", ZoneName: "example.com", BackupDir: filepath.Join(t.TempDir(), "backups"), Actor: "test"}
	return x, f
}

func load(t *testing.T, x *Executor, phase string) State {
	t.Helper()
	st, err := x.Load(context.Background(), phase)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAddEditMoveDeleteRestore(t *testing.T) {
	x, f := setup(t)
	ctx := context.Background()
	orig := f.snapshot(cfapi.PhaseCustom)

	// add before #2
	st := load(t, x, cfapi.PhaseCustom)
	p, err := st.PlanAdd(CustomRule(`starts_with(http.request.uri.path, "/login")`, "challenge login", "managed_challenge", true), "2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Lines, "\n"), "as #2, before") {
		t.Errorf("plan lines %v", p.Lines)
	}
	res, err := x.Apply(ctx, st, p)
	if err != nil || !res.Verified || res.BackupID == 0 {
		t.Fatalf("add: %+v %v", res, err)
	}
	if _, err := os.Stat(res.BackupFile); err != nil {
		t.Fatalf("backup file: %v", err)
	}
	if f.phases[cfapi.PhaseCustom].Rules[1]["description"] != "challenge login" {
		t.Fatal("not inserted at #2")
	}

	// edit: disable it
	st = load(t, x, cfapi.PhaseCustom)
	p, err = st.PlanEdit("2", map[string]any{"enabled": false})
	if err != nil || !strings.Contains(strings.Join(p.Lines, "\n"), "enabled:") {
		t.Fatalf("edit plan %v %v", p.Lines, err)
	}
	if _, err := x.Apply(ctx, st, p); err != nil {
		t.Fatal(err)
	}

	// edit keeps unknown fields (logging, action_parameters) of the skip rule
	st = load(t, x, cfapi.PhaseCustom)
	p, _ = st.PlanEdit("3", map[string]any{"description": "skip office monitors"})
	if _, err := x.Apply(ctx, st, p); err != nil {
		t.Fatal(err)
	}
	if r := f.phases[cfapi.PhaseCustom].Rules[2]; r["logging"] == nil || r["action_parameters"] == nil {
		t.Fatalf("fields lost on edit: %v", r)
	}

	// move #1 to the end
	st = load(t, x, cfapi.PhaseCustom)
	p, err = st.PlanMove("1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Apply(ctx, st, p); err != nil {
		t.Fatal(err)
	}
	if last := f.phases[cfapi.PhaseCustom].Rules[3]; last["description"] != "Block WP probes" {
		t.Fatalf("move: %v", last["description"])
	}

	// delete the login rule (now #1)
	st = load(t, x, cfapi.PhaseCustom)
	p, err = st.PlanDelete("1")
	if err != nil || p.Old["description"] != "challenge login" {
		t.Fatalf("delete plan %v %v", p.Old, err)
	}
	if _, err := x.Apply(ctx, st, p); err != nil {
		t.Fatal(err)
	}

	// restore the very first backup: original rules, order, fields
	backups, _ := x.Store.RuleBackups("z", cfapi.PhaseCustom, 10)
	first := backups[len(backups)-1]
	st, p, err = x.PlanRestore(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Lines, "\n"), "changed back") {
		t.Errorf("restore plan %v", p.Lines)
	}
	if res, err := x.Apply(ctx, st, p); err != nil || !res.Verified {
		t.Fatalf("restore: %+v %v", res, err)
	}
	now := f.snapshot(cfapi.PhaseCustom)
	for i := range orig.Rules {
		if !same(orig.Rules[i], now.Rules[i]) {
			t.Fatalf("rule %d differs after restore:\n%v\n%v", i, orig.Rules[i], now.Rules[i])
		}
	}

	log, _ := x.Store.RuleChanges("z", 20)
	ops := []string{}
	for _, c := range log {
		if !c.Verified {
			t.Errorf("unverified change %+v", c)
		}
		ops = append(ops, c.Op)
	}
	if strings.Join(ops, ",") != "restore,delete,move,edit,edit,add" {
		t.Fatalf("audit log %v", ops)
	}
}

func TestGuards(t *testing.T) {
	x, f := setup(t)
	st := load(t, x, cfapi.PhaseCustom)
	if _, err := st.PlanEdit("flarehound-asn-challenge", map[string]any{"enabled": false}); err == nil || !strings.Contains(err.Error(), "blocking module") {
		t.Fatalf("managed rule edit: %v", err)
	}
	if _, err := st.PlanDelete("3"); err == nil {
		t.Fatal("managed rule delete allowed")
	}
	if _, err := st.PlanAdd(CustomRule(`http.request.uri.path eq`, "bad", "block", true), ""); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("bad expression: %v", err)
	}
	if _, err := st.PlanEdit("1", map[string]any{"description": "Block WP probes"}); err == nil {
		t.Fatal("no-op edit accepted")
	}
	f.seed(cfapi.PhaseCustom, map[string]any{"a": 1}, map[string]any{"a": 2}, map[string]any{"a": 3}, map[string]any{"a": 4}, map[string]any{"a": 5})
	st = load(t, x, cfapi.PhaseCustom)
	if _, err := st.PlanAdd(CustomRule("true", "x", "block", true), ""); err == nil || !strings.Contains(err.Error(), "quota is full: 5 of 5") {
		t.Fatalf("quota: %v", err)
	}
}

func TestRateLimitQuotaAndCachePermission(t *testing.T) {
	x, f := setup(t)
	f.seed(cfapi.PhaseRateLimit, RateLimitRule(`starts_with(http.request.uri.path, "/rest/")`, "existing", "block", 150, 10, 10))
	st := load(t, x, cfapi.PhaseRateLimit)
	if _, err := st.PlanAdd(RateLimitRule(`http.request.uri.path eq "/rank"`, "rl", "managed_challenge", 20, 10, 10), ""); err == nil || !strings.Contains(err.Error(), "1 of 1") {
		t.Fatalf("rate-limit quota: %v", err)
	}
	if err := CheckRateLimit("free", 60, 10); err == nil {
		t.Fatal("free plan 60s period accepted")
	}
	f.denied[cfapi.PhaseCache] = true
	if _, err := x.Load(context.Background(), cfapi.PhaseCache); err == nil || !strings.Contains(err.Error(), "Cache Rules: Edit") {
		t.Fatalf("cache permission: %v", err)
	}
}

func TestFirstRuleInEmptyPhaseAndCacheShape(t *testing.T) {
	x, f := setup(t)
	st := load(t, x, cfapi.PhaseCache)
	if st.Found {
		t.Fatal("cache phase should be empty")
	}
	p, err := st.PlanAdd(CacheRule(`http.request.uri.path eq "/app.js"`, "cache app.js", 86400), "")
	if err != nil {
		t.Fatal(err)
	}
	if res, err := x.Apply(context.Background(), st, p); err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	raw, _ := json.Marshal(f.phases[cfapi.PhaseCache].Rules[0]["action_parameters"])
	if !strings.Contains(string(raw), `"edge_ttl":{"default":86400,"mode":"override_origin"}`) {
		t.Fatalf("cache rule shape %s", raw)
	}
}

func TestReadBackMismatchIsReported(t *testing.T) {
	x, f := setup(t)
	f.corrupt = true
	st := load(t, x, cfapi.PhaseCustom)
	p, _ := st.PlanAdd(CustomRule(`http.request.uri.path eq "/x"`, "x", "block", true), "")
	res, err := x.Apply(context.Background(), st, p)
	if err == nil || res.Verified || !strings.Contains(err.Error(), "flarehound rules restore") {
		t.Fatalf("mismatch not reported: %+v %v", res, err)
	}
	log, _ := x.Store.RuleChanges("z", 1)
	if len(log) != 1 || log[0].Verified {
		t.Fatalf("audit %+v", log)
	}
}

func TestSkipNeedsParameters(t *testing.T) {
	st := State{Phase: cfapi.PhaseCustom, Plan: "pro", Ruleset: cfapi.RawRuleset{Rules: []map[string]any{
		{"id": "s1", "action": "skip", "expression": "cf.client.bot", "description": "bots", "enabled": true,
			"action_parameters": map[string]any{"ruleset": "current"}},
		{"id": "b1", "action": "block", "expression": `ip.src eq 192.0.2.1`, "description": "bad ip", "enabled": true},
	}}}
	if _, err := st.PlanAdd(CustomRule("cf.client.bot", "x", "skip", true), ""); err == nil || !strings.Contains(err.Error(), "--skip") {
		t.Fatalf("skip rule without parameters accepted: %v", err)
	}
	p, err := st.PlanEdit("s1", map[string]any{"action": "managed_challenge"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.New["action_parameters"]; ok {
		t.Fatal("skip parameters kept on a non-skip rule")
	}
	if _, err := st.PlanEdit("b1", map[string]any{"action": "skip"}); err == nil {
		t.Fatal("block turned into skip without saying what it skips")
	}
	if _, err := st.PlanEdit("b1", map[string]any{"action": "skip", "action_parameters": map[string]any{"ruleset": "current"}}); err != nil {
		t.Fatalf("block → skip with parameters: %v", err)
	}
}
