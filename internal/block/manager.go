package block

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// API is the write-side Cloudflare surface the manager uses.
type API interface {
	ZonePlan(ctx context.Context, zoneID string) (string, error)
	Entrypoint(ctx context.Context, zoneID string) (cfapi.Ruleset, bool, error)
	CreateEntrypoint(ctx context.Context, zoneID string, r cfapi.Rule) (cfapi.Ruleset, error)
	AddRule(ctx context.Context, zoneID, rulesetID string, r cfapi.Rule) (cfapi.Ruleset, error)
	UpdateRule(ctx context.Context, zoneID, rulesetID string, r cfapi.Rule) (cfapi.Ruleset, error)
	DeleteRule(ctx context.Context, zoneID, rulesetID, ruleID string) (cfapi.Ruleset, error)
	Lists(ctx context.Context, accountID string) ([]cfapi.List, error)
	CreateList(ctx context.Context, accountID, name, description string) (cfapi.List, error)
	ListItems(ctx context.Context, accountID, listID string) ([]cfapi.ListItem, error)
	AddListItems(ctx context.Context, accountID, listID string, items []cfapi.ListItem) error
	DeleteListItems(ctx context.Context, accountID, listID string, ids []string) error
	AccessRules(ctx context.Context, zoneID, notesContains string) ([]cfapi.AccessRule, error)
	CreateAccessRule(ctx context.Context, zoneID, mode, target, value, notes string) (cfapi.AccessRule, error)
	DeleteAccessRule(ctx context.Context, zoneID, id string) error
}

type Mechanism string

const (
	MechRule   Mechanism = "custom_rule"
	MechList   Mechanism = "ip_list"
	MechAccess Mechanism = "access_rule"
)

// AccessNotes prefixes the notes of every IP Access Rule FlareHound owns.
const AccessNotes = "flarehound:"

// CustomRuleLimit is the custom-rule quota per plan (SPEC 16).
var CustomRuleLimit = map[string]int{"free": 5, "pro": 20, "business": 100, "enterprise": 1000}

// Entry is one blocked object as it exists in Cloudflare.
type Entry struct {
	Target    Target
	Action    Action
	Mechanism Mechanism
	RuleID    string // custom rule id (rule / list mechanism) or access rule id
	ItemID    string // list item id
}

// State is the zone's FlareHound-owned blocking objects.
type State struct {
	Plan          string
	Ruleset       cfapi.Ruleset
	HasEntrypoint bool
	Rules         map[string]cfapi.Rule // ref -> rule
	List          *cfapi.List
	ListItems     []cfapi.ListItem
	Access        []cfapi.AccessRule
	// Mechanisms the write token cannot use (missing permission); planning
	// avoids them and says why.
	NoLists  bool // Account Filter Lists
	NoAccess bool // Firewall Services (IP Access Rules)
}

// RulesUsed counts every rule in the custom-rules phase (the user's too:
// the quota is shared).
func (s State) RulesUsed() int { return len(s.Ruleset.Rules) }

// RuleLimit is the plan's custom-rule quota (5 if the plan is unknown).
func (s State) RuleLimit() int {
	if n, ok := CustomRuleLimit[s.Plan]; ok {
		return n
	}
	return 5
}

type Manager struct {
	API       API
	ZoneID    string
	AccountID string
}

func ownRef(r cfapi.Rule) string {
	for _, s := range []string{r.Ref, r.Description} {
		if strings.HasPrefix(s, "flarehound-") {
			return strings.Fields(s)[0]
		}
	}
	return ""
}

func description(ref string) string {
	return ref + " (managed by FlareHound — change it with `flarehound block/unblock`, not by hand)"
}

// Load reads the current FlareHound-owned state from Cloudflare.
func (m *Manager) Load(ctx context.Context) (State, error) {
	var st State
	var err error
	if st.Plan, err = m.API.ZonePlan(ctx, m.ZoneID); err != nil {
		return st, fmt.Errorf("zone plan: %w", err)
	}
	if st.Ruleset, st.HasEntrypoint, err = m.API.Entrypoint(ctx, m.ZoneID); err != nil {
		return st, fmt.Errorf("custom rules: %w", err)
	}
	st.Rules = map[string]cfapi.Rule{}
	for _, r := range st.Ruleset.Rules {
		if ref := ownRef(r); ref != "" {
			st.Rules[ref] = r
		}
	}
	if m.AccountID != "" {
		lists, err := m.API.Lists(ctx, m.AccountID)
		if cfapi.IsPermission(err) {
			st.NoLists = true
		} else if err != nil {
			return st, fmt.Errorf("IP lists: %w", err)
		}
		for i := range lists {
			if lists[i].Name == ListName {
				st.List = &lists[i]
			}
		}
		if st.List != nil {
			if st.ListItems, err = m.API.ListItems(ctx, m.AccountID, st.List.ID); err != nil {
				return st, fmt.Errorf("IP list items: %w", err)
			}
		}
	} else {
		st.NoLists = true
	}
	if st.Access, err = m.API.AccessRules(ctx, m.ZoneID, AccessNotes); cfapi.IsPermission(err) {
		st.NoAccess = true
	} else if err != nil {
		return st, fmt.Errorf("IP access rules: %w", err)
	}
	return st, nil
}

// Entries flattens the state into blocked objects.
func (s State) Entries() ([]Entry, error) {
	var out []Entry
	for _, t := range []Type{IP, ASN, Country, UA} {
		for _, a := range []Action{Block, Challenge} {
			r, ok := s.Rules[RuleRef(t, a)]
			if !ok {
				continue
			}
			if t == IP && a == Block && r.Expression == ListExpression {
				for _, it := range s.ListItems {
					tg, err := Parse("ip", it.IP)
					if err != nil {
						continue
					}
					out = append(out, Entry{Target: tg, Action: Block, Mechanism: MechList, RuleID: r.ID, ItemID: it.ID})
				}
				continue
			}
			vals, err := ParseExpression(t, r.Expression)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", RuleRef(t, a), err)
			}
			for _, v := range vals {
				out = append(out, Entry{Target: Target{t, v}, Action: a, Mechanism: MechRule, RuleID: r.ID})
			}
		}
	}
	for _, ar := range s.Access {
		var tg Target
		var err error
		switch ar.Configuration.Target {
		case "asn":
			tg, err = Parse("asn", ar.Configuration.Value)
		case "ip", "ip_range", "ip6":
			tg, err = Parse("ip", ar.Configuration.Value)
		default:
			continue
		}
		if err != nil {
			continue
		}
		a := Block
		if ar.Mode != "block" {
			a = Challenge
		}
		out = append(out, Entry{Target: tg, Action: a, Mechanism: MechAccess, RuleID: ar.ID})
	}
	return out, nil
}

// Find returns the entries for one target.
func (s State) Find(t Target) ([]Entry, error) {
	all, err := s.Entries()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range all {
		if e.Target == t {
			out = append(out, e)
		}
	}
	return out, nil
}

// Op is what Apply will do.
type Op string

const (
	OpNone             Op = "none"             // already blocked as asked
	OpCreateRule       Op = "create_rule"      // new FlareHound rule (uses quota)
	OpUpdateRule       Op = "update_rule"      // add a value to an existing FlareHound rule
	OpAddListItem      Op = "add_list_item"    // add to flarehound_block
	OpCreateListRule   Op = "create_list_rule" // create list (if needed) + the rule applying it
	OpCreateAccessRule Op = "create_access_rule"
)

// Plan is the exact change Apply will make; it is shown before the user
// confirms.
type Plan struct {
	Target     Target
	Action     Action
	Op         Op
	Mechanism  Mechanism
	RuleRef    string
	Expression string // rule expression after the change (rule mechanisms)
	Note       string // mechanism choice and quota, in plain words
}

func (s State) quotaLeft() int { return s.RuleLimit() - s.RulesUsed() }

// PlanBlock decides how to block t with action a, choosing the mechanism
// by plan and remaining quota (SPEC 13.1) and saying so.
func (s State) PlanBlock(t Target, a Action) (Plan, error) {
	p := Plan{Target: t, Action: a}
	existing, err := s.Find(t)
	if err != nil {
		return p, err
	}
	for _, e := range existing {
		if e.Action == a {
			p.Op, p.Mechanism = OpNone, e.Mechanism
			p.Note = fmt.Sprintf("%s is already blocked with action %s (%s)", t, a, e.Mechanism)
			return p, nil
		}
		return p, fmt.Errorf("%s is already handled with action %s; unblock it first to change the action", t, e.Action)
	}

	ref := RuleRef(t.Type, a)
	quota := fmt.Sprintf("custom rules in use: %d of %d (%s plan)", s.RulesUsed(), s.RuleLimit(), s.Plan)

	// IP block: the account list scales to thousands of entries.
	if t.Type == IP && a == Block {
		if r, ok := s.Rules[ref]; ok && r.Expression == ListExpression && s.List != nil {
			p.Op, p.Mechanism, p.RuleRef, p.Expression = OpAddListItem, MechList, ref, ListExpression
			p.Note = fmt.Sprintf("add to IP list %s (applied by rule %s); no extra rule needed", ListName, ref)
			return p, nil
		}
		if _, ok := s.Rules[ref]; !ok && s.quotaLeft() > 0 && !s.NoLists {
			p.Op, p.Mechanism, p.RuleRef, p.Expression = OpCreateListRule, MechList, ref, ListExpression
			p.Note = fmt.Sprintf("create IP list %s (account-wide) if missing, plus rule %s applying it — uses 1 custom rule once; %s", ListName, ref, quota)
			return p, nil
		}
	}

	if r, ok := s.Rules[ref]; ok {
		vals, err := ParseExpression(t.Type, r.Expression)
		if err != nil {
			return p, err
		}
		expr := Expression(t.Type, append(vals, t.Value))
		if len(expr) > MaxExpression {
			return p, fmt.Errorf("rule %s would exceed Cloudflare's %d-character expression limit; unblock stale entries first", ref, MaxExpression)
		}
		p.Op, p.Mechanism, p.RuleRef, p.Expression = OpUpdateRule, MechRule, ref, expr
		p.Note = fmt.Sprintf("add to existing rule %s; no extra rule needed", ref)
		return p, nil
	}
	if s.quotaLeft() > 0 {
		p.Op, p.Mechanism, p.RuleRef, p.Expression = OpCreateRule, MechRule, ref, Expression(t.Type, []string{t.Value})
		p.Note = fmt.Sprintf("create rule %s — uses 1 custom rule; %s", ref, quota)
		return p, nil
	}
	if _, _, err := AccessRuleTarget(t); err == nil && !s.NoAccess {
		p.Op, p.Mechanism = OpCreateAccessRule, MechAccess
		p.Note = fmt.Sprintf("custom-rule quota is full (%s): falling back to an IP Access Rule (no rule quota; no condition logic, so verified bots are NOT exempt)", quota)
		return p, nil
	}
	if _, _, err := AccessRuleTarget(t); err == nil && s.NoAccess {
		return p, fmt.Errorf("custom-rule quota is full (%s) and the write token has no Firewall Services: Edit for the IP Access Rule fallback; free a rule first", quota)
	}
	return p, fmt.Errorf("custom-rule quota is full (%s) and %s cannot use IP Access Rules; free a rule or merge existing ones first", quota, t)
}

// Apply executes a plan and verifies by reading the state back.
func (m *Manager) Apply(ctx context.Context, st State, p Plan, comment string) (Entry, error) {
	switch p.Op {
	case OpNone:
	case OpCreateRule, OpUpdateRule:
		if err := m.putRule(ctx, st, p.RuleRef, p.Action, p.Expression); err != nil {
			return Entry{}, err
		}
	case OpAddListItem:
		if err := m.API.AddListItems(ctx, m.AccountID, st.List.ID, []cfapi.ListItem{{IP: p.Target.Value, Comment: clip(comment, 400)}}); err != nil {
			return Entry{}, err
		}
	case OpCreateListRule:
		list := st.List
		if list == nil {
			l, err := m.API.CreateList(ctx, m.AccountID, ListName, "Managed by FlareHound: IPs blocked with `flarehound block ip`")
			if err != nil {
				// The plan may not allow another list: degrade to an
				// expression rule, which needs the same single rule.
				expr := Expression(IP, []string{p.Target.Value})
				if err2 := m.putRule(ctx, st, p.RuleRef, p.Action, expr); err2 != nil {
					return Entry{}, fmt.Errorf("create IP list: %v; expression-rule fallback: %w", err, err2)
				}
				break
			}
			list = &l
		}
		if err := m.API.AddListItems(ctx, m.AccountID, list.ID, []cfapi.ListItem{{IP: p.Target.Value, Comment: clip(comment, 400)}}); err != nil {
			return Entry{}, err
		}
		if err := m.putRule(ctx, st, p.RuleRef, p.Action, ListExpression); err != nil {
			return Entry{}, err
		}
	case OpCreateAccessRule:
		target, value, err := AccessRuleTarget(p.Target)
		if err != nil {
			return Entry{}, err
		}
		if _, err := m.API.CreateAccessRule(ctx, m.ZoneID, p.Action.CF(), target, value, AccessNotes+" "+clip(comment, 400)); err != nil {
			return Entry{}, err
		}
	default:
		return Entry{}, fmt.Errorf("unknown plan op %q", p.Op)
	}
	return m.verify(ctx, p.Target, p.Action, true)
}

func (m *Manager) putRule(ctx context.Context, st State, ref string, a Action, expr string) error {
	rule := cfapi.Rule{Ref: ref, Description: description(ref), Action: a.CF(), Expression: expr, Enabled: true}
	if old, ok := st.Rules[ref]; ok {
		rule.ID = old.ID
		_, err := m.API.UpdateRule(ctx, m.ZoneID, st.Ruleset.ID, rule)
		return err
	}
	if !st.HasEntrypoint {
		_, err := m.API.CreateEntrypoint(ctx, m.ZoneID, rule)
		return err
	}
	_, err := m.API.AddRule(ctx, m.ZoneID, st.Ruleset.ID, rule)
	return err
}

// verify re-reads Cloudflare and checks the target is (or is no longer)
// blocked as intended (SPEC 13.2 read-back verification).
func (m *Manager) verify(ctx context.Context, t Target, a Action, want bool) (Entry, error) {
	st, err := m.Load(ctx)
	if err != nil {
		return Entry{}, fmt.Errorf("read-back failed — the change may or may not be live, check the dashboard: %w", err)
	}
	es, err := st.Find(t)
	if err != nil {
		return Entry{}, err
	}
	for _, e := range es {
		if want && e.Action == a {
			return e, nil
		}
	}
	if !want && len(es) == 0 {
		return Entry{}, nil
	}
	if want {
		return Entry{}, fmt.Errorf("read-back: %s is not blocked after the change — check the dashboard", t)
	}
	return Entry{}, fmt.Errorf("read-back: %s is still present after unblocking — check the dashboard", t)
}

// ErrNotBlocked is returned by Unblock when nothing matched.
var ErrNotBlocked = errors.New("not blocked by FlareHound")

// Unblock removes t from every FlareHound mechanism that holds it.
// Rules left empty are deleted, freeing their quota.
func (m *Manager) Unblock(ctx context.Context, st State, t Target) ([]Entry, error) {
	es, err := st.Find(t)
	if err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, ErrNotBlocked
	}
	for _, e := range es {
		switch e.Mechanism {
		case MechAccess:
			if err := m.API.DeleteAccessRule(ctx, m.ZoneID, e.RuleID); err != nil {
				return nil, err
			}
		case MechList:
			if err := m.API.DeleteListItems(ctx, m.AccountID, st.List.ID, []string{e.ItemID}); err != nil {
				return nil, err
			}
			if len(st.ListItems) == 1 { // that was the last one: drop the rule too
				if _, err := m.API.DeleteRule(ctx, m.ZoneID, st.Ruleset.ID, e.RuleID); err != nil {
					return nil, err
				}
			}
		case MechRule:
			ref := RuleRef(t.Type, e.Action)
			r := st.Rules[ref]
			vals, err := ParseExpression(t.Type, r.Expression)
			if err != nil {
				return nil, err
			}
			vals = slices.DeleteFunc(vals, func(v string) bool { return v == t.Value })
			if len(vals) == 0 {
				if _, err := m.API.DeleteRule(ctx, m.ZoneID, st.Ruleset.ID, r.ID); err != nil {
					return nil, err
				}
			} else if err := m.putRule(ctx, st, ref, e.Action, Expression(t.Type, vals)); err != nil {
				return nil, err
			}
		}
	}
	if _, err := m.verify(ctx, t, "", false); err != nil {
		return es, err
	}
	return es, nil
}

// Sorted returns entries in a stable display order.
func Sorted(es []Entry) []Entry {
	out := append([]Entry(nil), es...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target.Type != out[j].Target.Type {
			return out[i].Target.Type < out[j].Target.Type
		}
		return out[i].Target.Value < out[j].Target.Value
	})
	return out
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
