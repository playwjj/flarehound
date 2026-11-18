// Package ruleexec is the general execution module (SPEC 13.2): it
// applies one rule change at a time to a zone's custom rules, rate-limit
// rules or cache rules, under the module's hard constraints —
//
//   - a separate write token (the watch process never holds it);
//   - the full change is shown and confirmed item by item (the CLI owns
//     the prompt; there is no "apply everything" mode);
//   - the phase is backed up before every change (archive + JSON file);
//   - the result is read back and compared field by field and by position;
//   - every execution is appended to an audit log;
//   - any backup can be restored, under the same confirm/verify rules.
//
// Rules are handled as raw JSON objects so nothing Cloudflare returns is
// lost on the way through.
package ruleexec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/store"
	"github.com/playwjj/flarehound/internal/waf"
)

// Phases the module manages, by short name.
var Phases = map[string]string{
	"custom":    cfapi.PhaseCustom,
	"ratelimit": cfapi.PhaseRateLimit,
	"cache":     cfapi.PhaseCache,
}

// PhaseName returns the short name of a Cloudflare phase.
func PhaseName(phase string) string {
	for k, v := range Phases {
		if v == phase {
			return k
		}
	}
	return phase
}

// Rule quota per plan and phase (SPEC 16).
var limits = map[string]map[string]int{
	cfapi.PhaseCustom:    {"free": 5, "pro": 20, "business": 100, "enterprise": 1000},
	cfapi.PhaseRateLimit: {"free": 1, "pro": 2, "business": 5, "enterprise": 100},
	cfapi.PhaseCache:     {"free": 10, "pro": 25, "business": 50, "enterprise": 300},
}

// API is the write-token REST surface.
type API interface {
	ZonePlan(ctx context.Context, zoneID string) (string, error)
	PhaseRuleset(ctx context.Context, zoneID, phase string) (cfapi.RawRuleset, bool, error)
	PutPhaseRules(ctx context.Context, zoneID, phase string, rules []map[string]any) (cfapi.RawRuleset, error)
	AddRuleRaw(ctx context.Context, zoneID, rulesetID string, rule, position map[string]any) (cfapi.RawRuleset, error)
	UpdateRuleRaw(ctx context.Context, zoneID, rulesetID, ruleID string, rule, position map[string]any) (cfapi.RawRuleset, error)
	DeleteRuleRaw(ctx context.Context, zoneID, rulesetID, ruleID string) (cfapi.RawRuleset, error)
}

type Executor struct {
	API       API
	Store     *store.Store
	ZoneID    string
	ZoneName  string
	BackupDir string // e.g. data/backups
	Actor     string
	Now       func() time.Time
}

func (x *Executor) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

// State is one phase as it is now.
type State struct {
	Phase   string
	Plan    string
	Found   bool
	Ruleset cfapi.RawRuleset
}

func (s State) Limit() int {
	if n, ok := limits[s.Phase][s.Plan]; ok {
		return n
	}
	return limits[s.Phase]["free"]
}

// Load reads one phase.
func (x *Executor) Load(ctx context.Context, phase string) (State, error) {
	st := State{Phase: phase}
	plan, err := x.API.ZonePlan(ctx, x.ZoneID)
	if err != nil {
		return st, fmt.Errorf("zone plan: %w", err)
	}
	st.Plan = plan
	st.Ruleset, st.Found, err = x.API.PhaseRuleset(ctx, x.ZoneID, phase)
	if err != nil {
		if cfapi.IsPermission(err) {
			return st, fmt.Errorf("the write token cannot access %s rules (%v); grant %s", PhaseName(phase), err, permFor(phase))
		}
		return st, err
	}
	return st, nil
}

func permFor(phase string) string {
	if phase == cfapi.PhaseCache {
		return "Zone → Cache Rules: Edit"
	}
	return "Zone → WAF: Edit"
}

// ---- rule helpers ----

func str(r map[string]any, k string) string { s, _ := r[k].(string); return s }

// Managed reports whether a rule belongs to the blocking module; the
// execution module never edits those (use block/unblock).
func Managed(r map[string]any) bool {
	return strings.HasPrefix(str(r, "ref"), "flarehound-") || strings.HasPrefix(str(r, "description"), "flarehound-")
}

// Find resolves a rule by 1-based position or by id.
func (s State) Find(sel string) (int, map[string]any, error) {
	rules := s.Ruleset.Rules
	if n, err := strconv.Atoi(strings.TrimPrefix(sel, "#")); err == nil {
		if n < 1 || n > len(rules) {
			return 0, nil, fmt.Errorf("no rule #%d (the %s phase has %d)", n, PhaseName(s.Phase), len(rules))
		}
		return n - 1, rules[n-1], nil
	}
	for i, r := range rules {
		if str(r, "id") == sel || str(r, "ref") == sel {
			return i, r, nil
		}
	}
	return 0, nil, fmt.Errorf("no rule %q in the %s phase", sel, PhaseName(s.Phase))
}

// ---- plans ----

type Op string

const (
	OpAdd     Op = "add"
	OpEdit    Op = "edit"
	OpDelete  Op = "delete"
	OpMove    Op = "move"
	OpRestore Op = "restore"
)

// Plan is the exact change; Lines is what the user confirms.
type Plan struct {
	Op       Op
	Phase    string
	Index    int            // target rule index (edit/delete/move); new index for add
	RuleID   string         // target rule id (edit/delete/move)
	Old      map[string]any // before (edit/delete/move)
	New      map[string]any // after (add/edit/move)
	Position map[string]any // {"before": id} / nil = end
	WantPos  int            // expected 0-based index after the change; -1: end; -2: n/a
	Restore  []map[string]any
	BackupID int64
	Lines    []string
	Warnings []string
}

func clone(r map[string]any) map[string]any {
	raw, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// checkSkip: Cloudflare rejects a skip rule that does not say what it
// skips; catch it before anything is sent, with the fix.
func checkSkip(r map[string]any) error {
	if str(r, "action") != "skip" {
		return nil
	}
	if ap, ok := r["action_parameters"].(map[string]any); !ok || len(ap) == 0 {
		return fmt.Errorf("a skip rule must say what it skips: add --skip rules (the remaining custom rules), or a list such as --skip rules,ratelimit")
	}
	return nil
}

func validateExpr(expr string) error {
	if strings.TrimSpace(expr) == "" {
		return fmt.Errorf("empty expression")
	}
	if _, err := waf.Parse(expr); err != nil {
		return fmt.Errorf("expression does not parse: %v", err)
	}
	return nil
}

func position(s State, before string) (map[string]any, int, error) {
	if before == "" {
		return nil, -1, nil
	}
	i, r, err := s.Find(before)
	if err != nil {
		return nil, 0, err
	}
	return map[string]any{"before": str(r, "id")}, i, nil
}

// PlanAdd plans a new rule, appended or placed before another rule.
func (s State) PlanAdd(rule map[string]any, before string) (Plan, error) {
	p := Plan{Op: OpAdd, Phase: s.Phase, New: clone(rule)}
	if err := checkSkip(rule); err != nil {
		return p, err
	}
	if err := validateExpr(str(rule, "expression")); err != nil {
		return p, err
	}
	if n, lim := len(s.Ruleset.Rules), s.Limit(); n >= lim {
		return p, fmt.Errorf("%s rule quota is full: %d of %d (%s plan); delete or merge a rule first", PhaseName(s.Phase), n, lim, s.Plan)
	}
	var err error
	if p.Position, p.WantPos, err = position(s, before); err != nil {
		return p, err
	}
	if p.New["ref"] == nil {
		p.New["ref"] = fmt.Sprintf("fhx-%d", time.Now().UnixNano())
	}
	where := fmt.Sprintf("at the end (#%d)", len(s.Ruleset.Rules)+1)
	if p.WantPos >= 0 {
		where = fmt.Sprintf("as #%d, before %s", p.WantPos+1, label(s.Ruleset.Rules[p.WantPos]))
	}
	p.Lines = append(p.Lines, fmt.Sprintf("ADD %s rule %s:", PhaseName(s.Phase), where))
	p.Lines = append(p.Lines, describe(p.New, "  + ")...)
	p.Lines = append(p.Lines, fmt.Sprintf("quota after: %d of %d (%s plan)", len(s.Ruleset.Rules)+1, s.Limit(), s.Plan))
	if p.WantPos >= 0 {
		p.Warnings = append(p.Warnings, "inserting ahead of existing rules changes what they see; check rules after it")
	}
	return p, nil
}

// PlanEdit plans a field update of one rule.
func (s State) PlanEdit(sel string, patch map[string]any) (Plan, error) {
	i, r, err := s.Find(sel)
	if err != nil {
		return Plan{}, err
	}
	if Managed(r) {
		return Plan{}, fmt.Errorf("%s is managed by the blocking module; use flarehound block/unblock", label(r))
	}
	p := Plan{Op: OpEdit, Phase: s.Phase, Index: i, RuleID: str(r, "id"), Old: clone(r), New: clone(r), WantPos: i}
	for k, v := range patch {
		if v == nil {
			delete(p.New, k)
		} else {
			p.New[k] = v
		}
	}
	// A skip rule's action_parameters say what it skips: they go with the
	// action, and other actions must not carry them.
	if str(p.Old, "action") == "skip" && str(p.New, "action") != "skip" && patch["action_parameters"] == nil {
		delete(p.New, "action_parameters")
	}
	if err := checkSkip(p.New); err != nil {
		return p, err
	}
	if err := validateExpr(str(p.New, "expression")); err != nil {
		return p, err
	}
	diff := diffRule(p.Old, p.New)
	if len(diff) == 0 {
		return p, fmt.Errorf("nothing to change: %s already has these values", label(r))
	}
	p.Lines = append(p.Lines, fmt.Sprintf("EDIT %s rule #%d %s:", PhaseName(s.Phase), i+1, label(r)))
	p.Lines = append(p.Lines, diff...)
	if p.New["enabled"] == false && p.Old["enabled"] != false {
		p.Warnings = append(p.Warnings, "disabling a rule removes its protection immediately")
	}
	return p, nil
}

// PlanDelete plans the removal of one rule.
func (s State) PlanDelete(sel string) (Plan, error) {
	i, r, err := s.Find(sel)
	if err != nil {
		return Plan{}, err
	}
	if Managed(r) {
		return Plan{}, fmt.Errorf("%s is managed by the blocking module; use flarehound unblock", label(r))
	}
	p := Plan{Op: OpDelete, Phase: s.Phase, Index: i, RuleID: str(r, "id"), Old: clone(r), WantPos: -2}
	p.Lines = append(p.Lines, fmt.Sprintf("DELETE %s rule #%d %s:", PhaseName(s.Phase), i+1, label(r)))
	p.Lines = append(p.Lines, describe(r, "  - ")...)
	if a := str(r, "action"); a == "block" || strings.Contains(a, "challenge") {
		p.Warnings = append(p.Warnings, "this removes a protection; the backup taken before the change can restore it")
	}
	return p, nil
}

// PlanMove plans a reorder: before another rule, or to the end ("").
func (s State) PlanMove(sel, before string) (Plan, error) {
	i, r, err := s.Find(sel)
	if err != nil {
		return Plan{}, err
	}
	if Managed(r) {
		return Plan{}, fmt.Errorf("%s is managed by the blocking module", label(r))
	}
	p := Plan{Op: OpMove, Phase: s.Phase, Index: i, RuleID: str(r, "id"), Old: clone(r), New: clone(r)}
	if before == "" {
		if i == len(s.Ruleset.Rules)-1 {
			return p, fmt.Errorf("%s is already last", label(r))
		}
		// The API has no "end" position for updates: place it after the last rule.
		p.Position = map[string]any{"after": str(s.Ruleset.Rules[len(s.Ruleset.Rules)-1], "id")}
		p.WantPos = len(s.Ruleset.Rules) - 1
	} else {
		j, b, err := s.Find(before)
		if err != nil {
			return p, err
		}
		if j == i || j == i+1 {
			return p, fmt.Errorf("%s is already right before %s", label(r), label(b))
		}
		p.Position = map[string]any{"before": str(b, "id")}
		p.WantPos = j
		if j > i {
			p.WantPos = j - 1
		}
	}
	p.Lines = append(p.Lines, fmt.Sprintf("MOVE %s rule #%d %s → #%d", PhaseName(s.Phase), i+1, label(r), p.WantPos+1))
	p.Warnings = append(p.Warnings, "rule order decides which rule acts first; skip rules ahead of a protection exempt from it")
	return p, nil
}

// ---- apply ----

// Result is one applied change.
type Result struct {
	BackupID   int64
	BackupFile string
	RuleID     string
	Verified   bool
	Detail     string
}

// Backup snapshots a phase (archive row + JSON file) and returns its id.
func (x *Executor) Backup(st State, reason string) (int64, string, error) {
	rules := st.Ruleset.Rules
	if rules == nil {
		rules = []map[string]any{}
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return 0, "", err
	}
	at := x.now()
	file := ""
	if x.BackupDir != "" {
		dir := filepath.Join(x.BackupDir, x.ZoneName)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return 0, "", err
		}
		file = filepath.Join(dir, fmt.Sprintf("%s-%s-v%s.json", PhaseName(st.Phase), at.UTC().Format("20060102-150405"), st.Ruleset.Version))
		pretty, _ := json.MarshalIndent(map[string]any{
			"zone": x.ZoneName, "zone_id": x.ZoneID, "phase": st.Phase, "version": st.Ruleset.Version,
			"taken_at": at.UTC(), "reason": reason, "rules": rules,
		}, "", "  ")
		if err := os.WriteFile(file, pretty, 0o600); err != nil {
			return 0, "", err
		}
	}
	if x.Store == nil {
		return 0, file, fmt.Errorf("the execution module needs the archive (backups and audit log live there)")
	}
	id, err := x.Store.AddRuleBackup(store.RuleBackup{At: at, Zone: x.ZoneID, Phase: st.Phase, Version: st.Ruleset.Version,
		Reason: reason, Data: string(data), File: file})
	return id, file, err
}

// Apply backs up the phase, makes the change, reads it back and records
// the execution. A failed verification is returned as an error naming the
// backup to restore.
func (x *Executor) Apply(ctx context.Context, st State, p Plan) (Result, error) {
	var res Result
	var err error
	res.BackupID, res.BackupFile, err = x.Backup(st, fmt.Sprintf("before %s", p.Op))
	if err != nil {
		return res, fmt.Errorf("backup failed, nothing changed: %w", err)
	}
	z, rsID := x.ZoneID, st.Ruleset.ID
	switch p.Op {
	case OpAdd:
		if !st.Found {
			_, err = x.API.PutPhaseRules(ctx, z, st.Phase, []map[string]any{p.New})
		} else {
			_, err = x.API.AddRuleRaw(ctx, z, rsID, p.New, p.Position)
		}
	case OpEdit:
		_, err = x.API.UpdateRuleRaw(ctx, z, rsID, p.RuleID, p.New, nil)
	case OpMove:
		_, err = x.API.UpdateRuleRaw(ctx, z, rsID, p.RuleID, p.New, p.Position)
	case OpDelete:
		_, err = x.API.DeleteRuleRaw(ctx, z, rsID, p.RuleID)
	case OpRestore:
		_, err = x.API.PutPhaseRules(ctx, z, st.Phase, p.Restore)
	default:
		err = fmt.Errorf("unknown op %s", p.Op)
	}
	if err != nil {
		x.record(st, p, res, false, "API error: "+err.Error())
		return res, fmt.Errorf("Cloudflare rejected the change (backup #%d taken): %w", res.BackupID, err)
	}

	after, err := x.Load(ctx, st.Phase)
	if err != nil {
		x.record(st, p, res, false, "read-back failed: "+err.Error())
		return res, fmt.Errorf("change sent but read-back failed — check the dashboard; restore with `flarehound rules restore %d`: %w", res.BackupID, err)
	}
	res.RuleID, res.Detail, res.Verified = verify(p, after)
	x.record(st, p, res, res.Verified, res.Detail)
	if !res.Verified {
		return res, fmt.Errorf("read-back mismatch: %s — restore with `flarehound rules restore %d`", res.Detail, res.BackupID)
	}
	return res, nil
}

func (x *Executor) record(st State, p Plan, res Result, ok bool, detail string) {
	if x.Store == nil {
		return
	}
	rule := p.RuleID
	if rule == "" && p.New != nil {
		rule = str(p.New, "ref")
	}
	if p.Op == OpRestore {
		rule = fmt.Sprintf("backup #%d", p.BackupID)
	}
	before, _ := json.Marshal(p.Old)
	after, _ := json.Marshal(p.New)
	if p.Op == OpRestore {
		after, _ = json.Marshal(p.Restore)
	}
	_ = x.Store.AddRuleChange(store.RuleChange{At: x.now(), Zone: x.ZoneID, Phase: st.Phase, Op: string(p.Op), Rule: rule,
		Before: string(before), After: string(after), BackupID: res.BackupID, Verified: ok, Detail: detail, Actor: x.Actor})
}

// same reports whether every field we set in want came back unchanged in
// got. Fields the server adds on its own (defaults, logging …) are
// allowed; ours must match exactly.
func same(want, got map[string]any) bool {
	w, g := norm(cfapi.Writable(want)), norm(cfapi.Writable(got))
	for k, v := range w {
		if !reflect.DeepEqual(v, g[k]) {
			return false
		}
	}
	return true
}

func norm(r map[string]any) map[string]any {
	out := clone(r)
	if _, ok := out["enabled"]; !ok {
		out["enabled"] = true
	}
	if d, ok := out["description"]; ok && d == "" {
		delete(out, "description")
	}
	return out
}

func verify(p Plan, after State) (ruleID, detail string, ok bool) {
	rules := after.Ruleset.Rules
	switch p.Op {
	case OpAdd:
		for i, r := range rules {
			if str(r, "ref") != str(p.New, "ref") {
				continue
			}
			if !same(p.New, r) {
				return str(r, "id"), "rule present but fields differ: " + strings.Join(diffRule(p.New, r), "; "), false
			}
			want := p.WantPos
			if want < 0 {
				want = len(rules) - 1
			}
			if i != want {
				return str(r, "id"), fmt.Sprintf("rule at #%d, expected #%d", i+1, want+1), false
			}
			return str(r, "id"), fmt.Sprintf("rule present as #%d, fields match", i+1), true
		}
		return "", "new rule not found after the change", false
	case OpEdit, OpMove:
		for i, r := range rules {
			if str(r, "id") != p.RuleID {
				continue
			}
			if !same(p.New, r) {
				return p.RuleID, "fields differ: " + strings.Join(diffRule(p.New, r), "; "), false
			}
			if i != p.WantPos {
				return p.RuleID, fmt.Sprintf("rule at #%d, expected #%d", i+1, p.WantPos+1), false
			}
			return p.RuleID, fmt.Sprintf("rule #%d matches", i+1), true
		}
		return p.RuleID, "rule not found after the change", false
	case OpDelete:
		for _, r := range rules {
			if str(r, "id") == p.RuleID {
				return p.RuleID, "rule still present", false
			}
		}
		return p.RuleID, "rule removed", true
	case OpRestore:
		if len(rules) != len(p.Restore) {
			return "", fmt.Sprintf("%d rules after restore, expected %d", len(rules), len(p.Restore)), false
		}
		for i := range rules {
			if !same(p.Restore[i], rules[i]) {
				return "", fmt.Sprintf("rule #%d differs: %s", i+1, strings.Join(diffRule(p.Restore[i], rules[i]), "; ")), false
			}
		}
		return "", fmt.Sprintf("%d rules match the backup, in order", len(rules)), true
	}
	return "", "", false
}

// ---- restore ----

// PlanRestore plans putting a phase back to a backup. The current state
// is backed up again by Apply, so a restore can itself be undone.
func (x *Executor) PlanRestore(ctx context.Context, backupID int64) (State, Plan, error) {
	if x.Store == nil {
		return State{}, Plan{}, fmt.Errorf("restore needs the archive")
	}
	b, ok, err := x.Store.RuleBackup(backupID)
	if err != nil {
		return State{}, Plan{}, err
	}
	if !ok || b.Zone != x.ZoneID {
		return State{}, Plan{}, fmt.Errorf("no backup #%d for zone %s", backupID, x.ZoneName)
	}
	var rules []map[string]any
	if err := json.Unmarshal([]byte(b.Data), &rules); err != nil {
		return State{}, Plan{}, fmt.Errorf("backup #%d is corrupt: %w", backupID, err)
	}
	st, err := x.Load(ctx, b.Phase)
	if err != nil {
		return st, Plan{}, err
	}
	p := Plan{Op: OpRestore, Phase: b.Phase, Restore: rules, BackupID: backupID, WantPos: -2}
	p.Lines = append(p.Lines, fmt.Sprintf("RESTORE %s rules to backup #%d (%s, version %s, %s):",
		PhaseName(b.Phase), b.ID, b.At.Format("2006-01-02 15:04 UTC"), b.Version, b.Reason))
	changes := diffSets(st.Ruleset.Rules, rules)
	if len(changes) == 0 {
		return st, p, fmt.Errorf("the %s rules already match backup #%d", PhaseName(b.Phase), backupID)
	}
	p.Lines = append(p.Lines, changes...)
	for _, r := range rules {
		if str(r, "ref") == "" {
			p.Warnings = append(p.Warnings, "some backed-up rules have no ref: Cloudflare may give them new IDs, restarting their per-rule hit history")
			break
		}
	}
	for _, r := range st.Ruleset.Rules {
		if Managed(r) {
			p.Warnings = append(p.Warnings, "FlareHound blocking rules are restored too — run `flarehound blocks` afterwards to reconcile")
			break
		}
	}
	return st, p, nil
}

// ---- rendering ----

func label(r map[string]any) string {
	d := str(r, "description")
	if d == "" {
		d = str(r, "id")
		if len(d) > 8 {
			d = d[:8]
		}
	}
	if len([]rune(d)) > 50 {
		d = string([]rune(d)[:50]) + "…"
	}
	return fmt.Sprintf("%q (%s)", d, str(r, "action"))
}

func show(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "(none)"
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

var fieldOrder = []string{"description", "action", "expression", "enabled", "action_parameters", "ratelimit", "logging", "ref"}

func keysOf(a, b map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range fieldOrder {
		_, ina := a[k]
		_, inb := b[k]
		if ina || inb {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				rest = append(rest, k)
			}
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func describe(r map[string]any, prefix string) []string {
	var out []string
	for _, k := range keysOf(cfapi.Writable(r), nil) {
		if k == "ref" && strings.HasPrefix(str(r, "ref"), "fhx-") {
			continue
		}
		out = append(out, fmt.Sprintf("%s%-12s %s", prefix, k+":", show(r[k])))
	}
	return out
}

func diffRule(a, b map[string]any) []string {
	a, b = norm(cfapi.Writable(a)), norm(cfapi.Writable(b))
	var out []string
	for _, k := range keysOf(a, b) {
		if !reflect.DeepEqual(a[k], b[k]) {
			out = append(out, fmt.Sprintf("  %s\n    - %s\n    + %s", k+":", show(a[k]), show(b[k])))
		}
	}
	return out
}

func ident(r map[string]any) string {
	if ref := str(r, "ref"); ref != "" {
		return ref
	}
	return str(r, "id")
}

func diffSets(cur, want []map[string]any) []string {
	var out []string
	curBy := map[string]int{}
	for i, r := range cur {
		curBy[ident(r)] = i
	}
	wantBy := map[string]bool{}
	for i, r := range want {
		wantBy[ident(r)] = true
		j, ok := curBy[ident(r)]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("  + #%d %s (comes back)", i+1, label(r)))
		case !same(cur[j], r):
			out = append(out, fmt.Sprintf("  ~ #%d %s (changed back):", i+1, label(r)))
			out = append(out, diffRule(cur[j], r)...)
		case i != j:
			out = append(out, fmt.Sprintf("  ↕ %s moves #%d → #%d", label(r), j+1, i+1))
		}
	}
	for i, r := range cur {
		if !wantBy[ident(r)] {
			out = append(out, fmt.Sprintf("  - #%d %s (removed)", i+1, label(r)))
		}
	}
	return out
}

// ---- builders for the suggestion types ----

// RateLimitRule builds a per-IP rate-limit rule (SPEC 9 rate-limit
// candidate). On Free the period and mitigation timeout must be 10 s.
func RateLimitRule(expr, desc, action string, requests, period, timeout int) map[string]any {
	return map[string]any{
		"description": desc, "expression": expr, "action": action, "enabled": true,
		"ratelimit": map[string]any{
			"characteristics": []any{"ip.src", "cf.colo.id"}, "period": float64(period),
			"requests_per_period": float64(requests), "mitigation_timeout": float64(timeout),
		},
	}
}

// CacheRule builds an edge-cache rule (SPEC 9 cache candidate).
func CacheRule(expr, desc string, ttlSeconds int) map[string]any {
	return map[string]any{
		"description": desc, "expression": expr, "action": "set_cache_settings", "enabled": true,
		"action_parameters": map[string]any{
			"cache":    true,
			"edge_ttl": map[string]any{"mode": "override_origin", "default": float64(ttlSeconds)},
		},
	}
}

// CustomRule builds a custom (WAF) rule.
func CustomRule(expr, desc, action string, enabled bool) map[string]any {
	return map[string]any{"description": desc, "expression": expr, "action": action, "enabled": enabled}
}

// CheckRateLimit validates rate-limit numbers against the plan.
func CheckRateLimit(plan string, period, timeout int) error {
	if plan == "free" || plan == "" {
		if period != 10 || timeout != 10 {
			return fmt.Errorf("on the Free plan rate-limit period and mitigation timeout must both be 10 seconds")
		}
	}
	if period <= 0 || timeout < 0 {
		return fmt.Errorf("period must be > 0 and timeout >= 0")
	}
	return nil
}
