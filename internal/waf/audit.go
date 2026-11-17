package waf

import (
	"sort"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// RuleRef identifies a rule in findings: position (1-based, in evaluation
// order), id and description.
type RuleRef struct {
	Pos         int    `json:"pos"`
	ID          string `json:"id"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// Path is one sensitive path to check coverage for.
type Path struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"` // "/login*"
}

// Hits is a rule's firewall-event count.
type Hits struct {
	D7, D30 int64
}

// Input is everything the audit looks at.
type Input struct {
	Hosts     []string // probe hosts (default: the zone name)
	Rules     []cfapi.Rule
	Sensitive []Path
	Plan      string          // "" when unknown
	Hits      map[string]Hits // rule id → hits; nil when unavailable
	HitsDays  int             // days the hit window covers (≤ 30; the zone's firewall-event retention)
	Access    []cfapi.AccessRule
	AccessNA  bool // IP Access Rules not readable
	Now       time.Time
}

// Coverage statuses.
const (
	Covered  = "covered"  // a protective rule always applies to the path
	Partial  = "partial"  // only depending on other fields (UA, IP …)
	Gap      = "gap"      // no protective rule applies
	Exempted = "exempted" // a skip rule ahead always lets it through
)

// Coverage is judged at two levels: any protection (challenge or block)
// and block level alone. An unconditional Managed Challenge covers a path
// — as a challenge: humans pass it, so the report must say which level.
type Coverage struct {
	Path      Path     `json:"path"`
	Host      string   `json:"host"`
	Status    string   `json:"status"`                // any protective action
	By        *RuleRef `json:"by,omitempty"`          // the protecting (or exempting) rule
	MaySkipBy *RuleRef `json:"may_skip_by,omitempty"` // a skip rule ahead that applies conditionally
	Level     string   `json:"level,omitempty"`       // "block" | "challenge": the action of By
	// Block level on its own (equal to Status when By already blocks).
	BlockStatus string   `json:"block_status"`
	BlockBy     *RuleRef `json:"block_by,omitempty"`
}

// probeFor is the request a coverage check asks about: an attacker on the
// path — by definition not a Cloudflare-verified bot, so conditions like
// "and not cf.client.bot" do not make a rule look conditional.
func probeFor(host, pattern string) Probe {
	return Probe{"http.host": host, "http.request.uri.path": ProbePath(pattern), "cf.client.bot": "false"}
}

// neutral is the probe moved to a path no rule targets.
func neutral(p Probe) Probe {
	q := Probe{}
	for k, v := range p {
		q[k] = v
	}
	q["http.request.uri.path"] = "/__flarehound_neutral_probe__"
	return q
}

// Blocking reports whether an action stops a request outright.
func Blocking(action string) bool { return action == "block" }

// Order finding kinds.
const (
	SkipShadows = "skip_shadows" // a skip rule ahead exempts everything a protective rule matches
	SkipOverlap = "skip_overlap" // a skip rule ahead exempts part of it (seen on a sensitive path)
	Shadowed    = "shadowed"     // an earlier block rule matches everything this rule matches
	Duplicate   = "duplicate"    // same condition, same action
)

type OrderFinding struct {
	Kind  string  `json:"kind"`
	Rule  RuleRef `json:"rule"`  // the rule that never (or not always) fires
	Cause RuleRef `json:"cause"` // the rule ahead of it
	Path  string  `json:"path,omitempty"`
}

// Exemption is one skip rule.
type Exemption struct {
	Rule      RuleRef  `json:"rule"`
	Skips     string   `json:"skips"` // what it skips
	Fields    []string `json:"fields"`
	Forgeable bool     `json:"forgeable"` // condition uses only client-controlled public fields
}

type Zombie struct {
	Rule    RuleRef `json:"rule"`
	AgeDays int     `json:"age_days"` // -1 unknown
}

type Quota struct {
	Used, Limit int
	Near        bool
	// Mergeable groups rules with the same action that could be OR-ed
	// into one rule (FlareHound-managed rules excluded).
	Mergeable [][]RuleRef
}

type ParseError struct {
	Rule RuleRef `json:"rule"`
	Err  string  `json:"err"`
}

// Result is the audit outcome.
type Result struct {
	Rules       int
	Disabled    int
	Coverage    []Coverage
	Order       []OrderFinding
	Exemptions  []Exemption
	HitsNA      bool
	Hits        map[string]Hits
	HitsDays    int
	Zombies     []Zombie
	Quota       Quota
	Access      []cfapi.AccessRule // allow / whitelist access rules (also exemptions)
	AccessNA    bool
	ParseErrors []ParseError
	RuleRefs    []RuleRef
}

// Problems counts the findings that deserve attention in a report.
func (r Result) Problems() int {
	n := len(r.Order) + len(r.Zombies) + len(r.ParseErrors) + len(r.Access)
	for _, c := range r.Coverage {
		if c.Status != Covered || c.MaySkipBy != nil {
			n++ // one item per path, however many reasons
		}
	}
	for _, e := range r.Exemptions {
		if e.Forgeable {
			n++
		}
	}
	if r.Quota.Near {
		n++
	}
	return n
}

// Protective reports whether an action stops or challenges a request.
func Protective(action string) bool {
	switch action {
	case "block", "challenge", "js_challenge", "managed_challenge":
		return true
	}
	return false
}

func skipsCurrent(r cfapi.Rule) bool {
	return r.Action == "skip" && r.ActionParameters != nil && r.ActionParameters.Ruleset == "current"
}

// forgeable fields are set freely by any client and carry no secret.
// Cookies and headers are excluded on purpose: they may hold a secret
// (a shared header token is a legitimate exemption).
var forgeable = map[string]bool{
	"http.user_agent": true, "http.referer": true, "http.host": true,
	"http.request.uri": true, "http.request.uri.path": true, "http.request.uri.query": true,
	"http.request.full_uri": true, "http.request.method": true, "http.request.version": true,
	"http.request.uri.path.extension": true, "raw.http.request.uri": true, "raw.http.request.uri.path": true,
	"raw.http.request.uri.query": true, "raw.http.request.full_uri": true, "http.x_forwarded_for": true,
}

// ProbePath turns a pattern into a concrete path: "/login*" → "/login",
// "/u/*/edit" → "/u/x/edit".
func ProbePath(pattern string) string {
	p := strings.TrimSuffix(pattern, "*")
	return strings.ReplaceAll(p, "*", "x")
}

// FlareHound-managed rules are excluded from merge advice.
func managed(r cfapi.Rule) bool {
	return strings.HasPrefix(r.Ref, "flarehound-") || strings.HasPrefix(r.Description, "flarehound-")
}

// limits mirror the per-plan custom-rule quota (SPEC 16).
var limits = map[string]int{"free": 5, "pro": 20, "business": 100, "enterprise": 1000}

// Audit runs every check.
func Audit(in Input) Result {
	res := Result{Rules: len(in.Rules), Hits: in.Hits, HitsNA: in.Hits == nil, HitsDays: in.HitsDays, AccessNA: in.AccessNA}
	if in.Hits != nil && in.HitsDays == 0 {
		res.HitsDays = 30 // callers that do not report coverage mean the full window
	}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	type parsed struct {
		r    cfapi.Rule
		ref  RuleRef
		node Node // nil: unparseable
	}
	var rules []parsed
	for i, r := range in.Rules {
		ref := RuleRef{Pos: i + 1, ID: r.ID, Description: r.Description, Action: r.Action}
		res.RuleRefs = append(res.RuleRefs, ref)
		if !r.Enabled {
			res.Disabled++
			continue
		}
		n, err := Parse(r.Expression)
		if err != nil {
			res.ParseErrors = append(res.ParseErrors, ParseError{Rule: ref, Err: err.Error()})
		}
		rules = append(rules, parsed{r, ref, n})
	}
	eval := func(p parsed, probe Probe) Tri {
		if p.node == nil {
			return Unknown
		}
		return Eval(p.node, probe)
	}

	// ---- coverage ----
	// scan walks the rules in order for one probe and one notion of
	// "protective"; a skip rule that always matches ends the walk.
	scan := func(probe Probe, protects func(string) bool) (status string, by, maySkip *RuleRef) {
		var partial *RuleRef
		for _, p := range rules {
			if p.node == nil {
				continue // reported as a parse error; no claim either way
			}
			t := eval(p, probe)
			if t == False {
				continue
			}
			ref := p.ref
			if skipsCurrent(p.r) {
				if t == True {
					return Exempted, &ref, maySkip
				}
				if maySkip == nil {
					maySkip = &ref
				}
				continue
			}
			if !protects(p.r.Action) {
				continue
			}
			if t == True {
				return Covered, &ref, maySkip
			}
			// Conditional coverage only counts for rules the path selects: a
			// rule that is just as "conditional" on an unrelated path (an IP
			// list, a crawler-UA block with a robots.txt exception) applies
			// to every path alike and protects none of them in particular.
			if partial == nil && eval(p, neutral(probe)) == False {
				partial = &ref
			}
		}
		if partial != nil {
			return Partial, partial, maySkip
		}
		return Gap, nil, maySkip
	}
	hosts := in.Hosts
	for _, sp := range in.Sensitive {
		for _, h := range hosts {
			probe := probeFor(h, sp.Pattern)
			c := Coverage{Path: sp, Host: h}
			c.Status, c.By, c.MaySkipBy = scan(probe, Protective)
			if c.By != nil && Protective(c.By.Action) {
				c.Level = "challenge"
				if Blocking(c.By.Action) {
					c.Level = "block"
				}
			}
			c.BlockStatus, c.BlockBy, _ = scan(probe, Blocking)
			res.Coverage = append(res.Coverage, c)
		}
	}

	// ---- order: skips ahead, shadows, duplicates ----
	seen := map[string]bool{}
	add := func(f OrderFinding) {
		k := f.Kind + f.Rule.ID + f.Cause.ID
		if !seen[k] {
			seen[k] = true
			res.Order = append(res.Order, f)
		}
	}
	for j, b := range rules {
		if b.node == nil || !Protective(b.r.Action) {
			continue
		}
		for _, a := range rules[:j] {
			if a.node == nil {
				continue
			}
			switch {
			case skipsCurrent(a.r):
				if Implies(b.node, a.node) {
					add(OrderFinding{Kind: SkipShadows, Rule: b.ref, Cause: a.ref})
					continue
				}
				for _, sp := range in.Sensitive {
					for _, h := range hosts {
						probe := probeFor(h, sp.Pattern)
						if eval(a, probe) != False && eval(b, probe) != False {
							add(OrderFinding{Kind: SkipOverlap, Rule: b.ref, Cause: a.ref, Path: sp.Pattern})
						}
					}
				}
			case a.r.Action == b.r.Action && key(a.node) == key(b.node):
				add(OrderFinding{Kind: Duplicate, Rule: b.ref, Cause: a.ref})
			case a.r.Action == "block" && Implies(b.node, a.node):
				add(OrderFinding{Kind: Shadowed, Rule: b.ref, Cause: a.ref})
			}
		}
	}

	// ---- exemptions ----
	for _, p := range rules {
		if p.r.Action != "skip" {
			continue
		}
		e := Exemption{Rule: p.ref, Skips: skipScope(p.r)}
		if p.node != nil {
			fs := Fields(p.node)
			e.Forgeable = len(fs) > 0
			for f := range fs {
				e.Fields = append(e.Fields, f)
				if !forgeable[f] {
					e.Forgeable = false
				}
			}
			sort.Strings(e.Fields)
		}
		res.Exemptions = append(res.Exemptions, e)
	}
	for _, a := range in.Access {
		if a.Mode == "whitelist" || a.Mode == "allow" {
			res.Access = append(res.Access, a)
		}
	}

	// ---- hits / zombies ----
	// Zombie claims need the full 30 days: on a zone that keeps 3 days of
	// firewall events, three quiet days prove nothing.
	if in.Hits != nil && res.HitsDays >= 30 {
		for _, p := range rules {
			if p.r.Action == "skip" || p.r.Action == "log" {
				continue // their events are not counted the same way
			}
			if in.Hits[p.r.ID].D30 > 0 {
				continue
			}
			age := -1
			if !p.r.LastUpdated.IsZero() {
				age = int(in.Now.Sub(p.r.LastUpdated).Hours() / 24)
			}
			if age >= 0 && age < 30 {
				continue // too new to call dead
			}
			res.Zombies = append(res.Zombies, Zombie{Rule: p.ref, AgeDays: age})
		}
	}

	// ---- quota ----
	res.Quota.Used = len(in.Rules)
	res.Quota.Limit = limits[in.Plan]
	if res.Quota.Limit > 0 && res.Quota.Used*10 >= res.Quota.Limit*8 {
		res.Quota.Near = true
		groups := map[string][]RuleRef{}
		var order []string
		for _, p := range rules {
			if managed(p.r) || p.r.ActionParameters != nil || !Protective(p.r.Action) {
				continue
			}
			if _, ok := groups[p.r.Action]; !ok {
				order = append(order, p.r.Action)
			}
			groups[p.r.Action] = append(groups[p.r.Action], p.ref)
		}
		for _, a := range order {
			if len(groups[a]) > 1 {
				res.Quota.Mergeable = append(res.Quota.Mergeable, groups[a])
			}
		}
	}
	return res
}

func skipScope(r cfapi.Rule) string {
	ap := r.ActionParameters
	if ap == nil {
		return "unspecified"
	}
	var parts []string
	if ap.Ruleset == "current" {
		parts = append(parts, "all remaining custom rules")
	}
	if len(ap.Phases) > 0 {
		parts = append(parts, "phases: "+strings.Join(ap.Phases, ", "))
	}
	if len(ap.Products) > 0 {
		parts = append(parts, "products: "+strings.Join(ap.Products, ", "))
	}
	if len(parts) == 0 {
		return "unspecified"
	}
	return strings.Join(parts, "; ")
}
