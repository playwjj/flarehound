package sim

// Phase 2: what the expression alone does not say.
//
//   - $lists: an account list the expression refers to is expanded into
//     its literal values through the Lists API (IP and ASN lists).
//   - Position: a rule only sees what the rules ahead of it let through.
//     Skip rules ahead of it (skipping the remaining custom rules) take
//     their share before it; the firewall events record those skips per
//     rule, so it costs no extra query. A skip rule that does not log is
//     counted from its own expression, or, when that cannot be
//     translated, net new becomes an upper bound.
//   - Challenge pass rate: the firewall events of the slice say how many
//     challenges were issued, solved, and passed with a clearance. Only
//     requests that met a challenge are in that sample — a reference
//     range, not a prediction.

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/waf"
)

// ListAPI reads account lists (Account → Account Filter Lists: Read).
type ListAPI interface {
	Lists(ctx context.Context, accountID string) ([]cfapi.List, error)
	ListItems(ctx context.Context, accountID, listID string) ([]cfapi.ListItem, error)
}

// RulesAPI reads the zone's custom rules (Zone → WAF: Read).
type RulesAPI interface {
	Entrypoint(ctx context.Context, zoneID string) (cfapi.Ruleset, bool, error)
}

// MaxListValues bounds an expanded list: a filter with thousands of
// values is not something the analytics API is meant to take.
const MaxListValues = 1000

// More reason codes.
const (
	whyListManaged = "list_managed" // $cf.* lists: contents not readable
	whyListAccess  = "list_access"  // the token cannot read account lists
	whyListMissing = "list_missing" // no list of that name
	whyListKind    = "list_kind"    // hostname / redirect lists
	whyListBig     = "list_big"     // more than MaxListValues items
	whyListRange   = "list_range"   // the IP list holds ranges
	whySkipNoLog   = "skip_nolog"   // a skip rule ahead logs nothing and cannot be translated
)

// listRes is one $list, resolved or not.
type listRes struct {
	kind string
	vals []string
	why  string
}

// ListUse is an expanded list, for the report.
type ListUse struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Items int    `json:"items"`
}

func listNames(n waf.Node) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(waf.Node)
	walk = func(x waf.Node) {
		switch y := x.(type) {
		case waf.And:
			walk(y.L)
			walk(y.R)
		case waf.Or:
			walk(y.L)
			walk(y.R)
		case waf.Xor:
			walk(y.L)
			walk(y.R)
		case waf.Not:
			walk(y.X)
		case waf.Cmp:
			if l, ok := y.Value.(waf.ListRef); ok && !seen[l.Name] {
				seen[l.Name] = true
				out = append(out, l.Name)
			}
		}
	}
	walk(n)
	return out
}

// resolveLists expands the $lists n refers to. A list that cannot be
// expanded keeps its reason; the expression is then not evaluable.
func resolveLists(ctx context.Context, n waf.Node, api ListAPI, account string) (map[string]listRes, []ListUse) {
	names := listNames(n)
	if len(names) == 0 {
		return nil, nil
	}
	out := map[string]listRes{}
	var lists []cfapi.List
	var listErr error
	fetched := false
	var uses []ListUse
	for _, name := range names {
		if strings.HasPrefix(name, "cf.") {
			out[name] = listRes{why: whyListManaged}
			continue
		}
		if api == nil || account == "" {
			out[name] = listRes{why: whyListAccess}
			continue
		}
		if !fetched {
			lists, listErr = api.Lists(ctx, account)
			fetched = true
		}
		if listErr != nil {
			out[name] = listRes{why: whyListAccess}
			continue
		}
		var l *cfapi.List
		for i := range lists {
			if lists[i].Name == name {
				l = &lists[i]
			}
		}
		switch {
		case l == nil:
			out[name] = listRes{why: whyListMissing}
			continue
		case l.Kind != "ip" && l.Kind != "asn":
			out[name] = listRes{why: whyListKind, kind: l.Kind}
			continue
		case l.NumItems > MaxListValues:
			out[name] = listRes{why: whyListBig, kind: l.Kind}
			continue
		}
		items, err := api.ListItems(ctx, account, l.ID)
		if err != nil {
			out[name] = listRes{why: whyListAccess}
			continue
		}
		res := listRes{kind: l.Kind}
		for _, it := range items {
			if l.Kind == "asn" {
				if it.ASN > 0 {
					res.vals = append(res.vals, strconv.Itoa(it.ASN))
				}
				continue
			}
			v := it.IP
			if p, err := netip.ParsePrefix(v); err == nil {
				if !p.IsSingleIP() {
					res = listRes{why: whyListRange, kind: l.Kind}
					break
				}
				v = p.Addr().String()
			}
			res.vals = append(res.vals, v)
		}
		if res.why == "" && len(res.vals) > MaxListValues {
			res = listRes{why: whyListBig, kind: l.Kind}
		}
		if res.why == "" {
			uses = append(uses, ListUse{Name: name, Kind: l.Kind, Items: len(res.vals)})
		}
		out[name] = res
	}
	return out, uses
}

// ---- position ----

// SkipRow is a skip rule ahead of the draft and what it lets through.
type SkipRow struct {
	Pos     int    `json:"pos"`
	Label   string `json:"label"`
	Count   int64  `json:"count"`
	NoLog   bool   `json:"no_log,omitempty"`  // counted from its expression (it logs nothing)
	Unknown bool   `json:"unknown,omitempty"` // logs nothing and cannot be translated
}

// position fixes the rules ahead of the draft: given by the caller (the
// block review knows the plan's position), or read and placed like a new
// FlareHound rule (or before rule in.Before).
func position(ctx context.Context, in *Input, r *Report) {
	if in.AheadKnown {
		r.PositionKnown = true
		r.Position = len(in.Ahead) + 1
		return
	}
	rules := in.Rules
	if rules == nil {
		if in.RulesAPI == nil {
			r.PositionWhy = "no_rules"
			return
		}
		rs, found, err := in.RulesAPI.Entrypoint(ctx, in.ZoneID)
		if err != nil {
			r.PositionWhy = "rules_unreadable"
			return
		}
		if found {
			rules = rs.Rules
		}
		in.Rules = rules
	}
	idx := block.DefaultIndex(rules)
	if in.Before > 0 {
		r.PositionChosen = true
		idx = min(in.Before-1, len(rules))
	}
	in.Ahead, in.AheadKnown = rules[:idx], true
	r.PositionKnown, r.Position = true, idx+1
	if idx < len(rules) {
		r.PosBefore = block.RuleLabel(rules[idx])
	}
}

// skipsAhead are the enabled rules ahead that skip the remaining custom
// rules, by ID, with their 1-based position.
func skipsAhead(ahead []cfapi.Rule) map[string]int {
	out := map[string]int{}
	for i, x := range ahead {
		if block.SkipsRest(x) {
			out[x.ID] = i + 1
		}
	}
	return out
}

// ---- challenge outcomes ----

// Challenge is the slice's challenge history in the firewall events.
type Challenge struct {
	Issued   int64 `json:"issued"`
	Solved   int64 `json:"solved"`
	Bypassed int64 `json:"bypassed"` // passed with an earlier clearance
	Failed   int64 `json:"failed"`
}

// ChallengeMin is the history below which no pass rate is given.
const ChallengeMin = 30

// Known reports whether the history is large enough to read.
func (c Challenge) Known() bool { return c.Issued+c.Bypassed >= ChallengeMin }

// Range is the reference range of requests that get through a challenge:
// at least the solved share of the challenges issued, at most that plus
// the requests that passed with a clearance.
func (c Challenge) Range() (lo, hi float64) {
	if c.Issued > 0 {
		lo = min(float64(c.Solved)/float64(c.Issued), 1)
	}
	if d := c.Issued + c.Bypassed; d > 0 {
		hi = min(float64(c.Solved+c.Bypassed)/float64(d), 1)
	}
	if hi < lo {
		hi = lo
	}
	return lo, hi
}

// add classifies one firewall action.
func (c *Challenge) add(action string, n int64) {
	a := strings.ToLower(strings.ReplaceAll(action, "_", ""))
	switch {
	case strings.Contains(a, "solved"):
		c.Solved += n
	case strings.Contains(a, "bypassed"):
		c.Bypassed += n
	case strings.Contains(a, "failed"):
		c.Failed += n
	case a == "challenge" || a == "jschallenge" || a == "managedchallenge":
		c.Issued += n
	}
}
