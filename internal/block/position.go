package block

// Where a FlareHound rule sits in the zone's custom rules (v1.16).
//
// Order is meaning: a rule only sees what the rules ahead of it let
// through. Appending at the end put a confirmed bad IP behind the zone's
// challenge rules (it kept eating challenge pages before reaching the
// block), and behind every skip rule (a target that matched one would
// never reach the block, with nothing said at review time).
//
// FlareHound rules go after every skip rule — those are the zone's guard
// rails (its own services, verified crawlers) and must stay ahead — and
// before the first challenge or block rule of the user's: a confirmed
// target need not be challenged first. An existing FlareHound rule that
// sits elsewhere is moved there once; after that, adding members does not
// move it.

import (
	"fmt"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/waf"
)

// Placement is where a FlareHound rule will sit after a change.
type Placement struct {
	Pos     int         // 1-based position the rule will hold
	After   *cfapi.Rule // the rule right ahead of it (nil: first)
	Before  *cfapi.Rule // the rule right after it (nil: last)
	Move    bool        // an existing FlareHound rule moves there (once)
	From    int         // its current 1-based position when Move
	Skips   int         // skip rules ahead of it
	Exists  bool        // the rule exists already (members are added to it)
	Ignored bool        // no placement (IP Access Rule, or nothing changes)
}

func protective(a string) bool {
	switch a {
	case "block", "challenge", "js_challenge", "managed_challenge":
		return true
	}
	return false
}

// SkipsRest reports whether a rule skips the remaining custom rules —
// the kind of skip that can exempt a target from a FlareHound rule.
func SkipsRest(r cfapi.Rule) bool {
	return r.Enabled && r.Action == "skip" && r.ActionParameters != nil && r.ActionParameters.Ruleset == "current"
}

// target computes the wanted index in rules (which do not hold the rule
// being placed): after the last enabled skip rule, before the first
// enabled challenge/block rule that is not FlareHound's.
func target(rules []cfapi.Rule) (idx, lastSkip int) {
	lastSkip = -1
	for i, r := range rules {
		if r.Enabled && r.Action == "skip" {
			lastSkip = i
		}
	}
	idx = len(rules)
	for i := lastSkip + 1; i < len(rules); i++ {
		if rules[i].Enabled && protective(rules[i].Action) && ownRef(rules[i]) == "" {
			idx = i
			break
		}
	}
	return idx, lastSkip
}

// DefaultIndex is where a new FlareHound rule would be inserted into
// rules (0-based: rules[:i] are ahead of it) — after the skip rules, ahead
// of the first challenge/block rule. The rule simulator uses it.
func DefaultIndex(rules []cfapi.Rule) int {
	idx, _ := target(rules)
	return idx
}

// Ahead returns the rules that will sit ahead of rule ref at position pos
// (1-based, as Place computes it; the rule itself left out).
func (s State) Ahead(ref string, pos int) []cfapi.Rule {
	var rest []cfapi.Rule
	for _, r := range s.Ruleset.Rules {
		if ownRef(r) != ref {
			rest = append(rest, r)
		}
	}
	if pos-1 < len(rest) && pos >= 1 {
		rest = rest[:pos-1]
	}
	return rest
}

// Place computes where the rule ref goes (see the package comment).
func (s State) Place(ref string) Placement {
	var rest []cfapi.Rule
	cur := -1
	for i, r := range s.Ruleset.Rules {
		if ownRef(r) == ref {
			cur = i
			continue
		}
		rest = append(rest, r)
	}
	idx, lastSkip := target(rest)
	p := Placement{Exists: cur >= 0}
	for i := 0; i < len(rest) && i <= lastSkip; i++ {
		if rest[i].Enabled && rest[i].Action == "skip" {
			p.Skips++
		}
	}
	// An existing rule already in the window (after the skips, not behind
	// a user's protective rule) stays where it is.
	if cur >= 0 && cur > lastSkip && cur <= idx {
		idx = cur
	} else if cur >= 0 {
		p.Move, p.From = true, cur+1
	}
	p.Pos = idx + 1
	if idx > 0 {
		r := rest[idx-1]
		p.After = &r
	}
	if idx < len(rest) {
		r := rest[idx]
		p.Before = &r
	}
	return p
}

// Position is the API position for creating (or moving) the rule; nil
// means "append" (creation at the end).
func (p Placement) Position(moving bool) *cfapi.Position {
	switch {
	case p.Before != nil:
		return &cfapi.Position{Before: p.Before.ID}
	case moving && p.After != nil:
		return &cfapi.Position{After: p.After.ID}
	}
	return nil
}

// RuleLabel names a rule for people: its description (shortened) and action.
func RuleLabel(r cfapi.Rule) string {
	d := r.Description
	if d == "" {
		d = r.Ref
	}
	if d == "" && len(r.ID) > 8 {
		d = r.ID[:8]
	}
	if len([]rune(d)) > 50 {
		d = string([]rune(d)[:50]) + "…"
	}
	return fmt.Sprintf("«%s» (%s)", d, r.Action)
}

// Describe says where the rule goes, in plain words.
func (p Placement) Describe() string {
	if p.Ignored {
		return ""
	}
	where := fmt.Sprintf("#%d", p.Pos)
	switch {
	case p.After != nil && p.Before != nil:
		where += fmt.Sprintf(", after %s and before %s", RuleLabel(*p.After), RuleLabel(*p.Before))
	case p.After != nil:
		where += fmt.Sprintf(", last, after %s", RuleLabel(*p.After))
	case p.Before != nil:
		where += fmt.Sprintf(", first, before %s", RuleLabel(*p.Before))
	}
	switch {
	case p.Move:
		return fmt.Sprintf("moves once from #%d to %s — after the zone's skip rules, ahead of its challenge/block rules", p.From, where)
	case p.Exists:
		return "stays at " + where
	}
	return "inserted at " + where
}

// Bypass is a skip rule ahead of a FlareHound rule that lets the target
// through: the block would never see it.
type Bypass struct {
	Rule  cfapi.Rule
	Pos   int     // 1-based
	UA    string  // the target's user agent that matches ("" when the target alone does)
	Share float64 // that UA's share of the target's traffic (0 when unknown)
}

func (b Bypass) String() string {
	s := fmt.Sprintf("this target is let through by skip rule #%d %s", b.Pos, RuleLabel(b.Rule))
	if b.UA != "" {
		s += fmt.Sprintf(" — its user agent %q", clip(b.UA, 80))
		if b.Share > 0 {
			s += fmt.Sprintf(" (%.0f%% of its requests)", b.Share*100)
		}
		s += " matches it"
	}
	return s + ": the block may have no effect on it"
}

// probe is what is known about every request of the target.
func probe(t Target) waf.Probe {
	p := waf.Probe{}
	switch t.Type {
	case IP:
		if pf, ok := t.Prefix(); ok && pf.IsSingleIP() {
			p["ip.src"] = pf.Addr().String()
		}
	case ASN:
		p["ip.src.asnum"], p["ip.geoip.asnum"] = t.Value, t.Value
	case Country:
		p["ip.src.country"], p["ip.geoip.country"] = t.Value, t.Value
	case UA:
		p["http.user_agent"] = t.Value
	}
	return p
}

// Bypasses evaluates the skip rules ahead of position pos (1-based)
// against the target and its observed user agents (profile: the target's
// top user agents with their counts, may be empty). Only a skip that is
// certain to match — for the target alone, or for one of its user
// agents — is reported: an undecided condition says nothing.
func (s State) Bypasses(t Target, ref string, pos int, profile []cfapi.Face) []Bypass {
	var total int64
	for _, f := range profile {
		total += f.Count
	}
	var out []Bypass
	n := 0
	for _, r := range s.Ruleset.Rules {
		if ownRef(r) == ref {
			continue
		}
		n++
		if n >= pos {
			break
		}
		if !SkipsRest(r) {
			continue
		}
		node, err := waf.Parse(r.Expression)
		if err != nil {
			continue
		}
		base := probe(t)
		if waf.Eval(node, base) == waf.True {
			out = append(out, Bypass{Rule: r, Pos: n})
			continue
		}
		for _, f := range profile {
			p := waf.Probe{}
			for k, v := range base {
				p[k] = v
			}
			p["http.user_agent"] = f.Name
			if waf.Eval(node, p) == waf.True {
				b := Bypass{Rule: r, Pos: n, UA: f.Name}
				if total > 0 {
					b.Share = float64(f.Count) / float64(total)
				}
				out = append(out, b)
				break
			}
		}
	}
	return out
}

// positionOf returns the 1-based position of rule ref (0: absent).
func (s State) positionOf(ref string) int {
	for i, r := range s.Ruleset.Rules {
		if ownRef(r) == ref {
			return i + 1
		}
	}
	return 0
}
