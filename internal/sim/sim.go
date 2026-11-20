// Package sim is the WAF rule simulator: it replays a draft rule
// expression against the last days of real traffic — as far as
// Cloudflare's aggregated analytics allow — and says what the rule would
// do: how much it matches, how much its own exemptions let through, how
// much existing rules already stop, what it is made of, and a verdict in
// the guard rails' terms.
//
// It only reads. There is no replay API (GraphQL analytics are sampled,
// aggregated datasets; per-request logs are Logpush, which FlareHound does
// not use), so the simulator translates the expression into dimension
// filters (see translate.go) and labels every report with how far its
// numbers can be trusted. It never dresses an upper bound up as a count.
package sim

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/suggest"
	"github.com/playwjj/flarehound/internal/waf"
)

// API is the read-token analytics the simulator queries.
type API interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
	Hourly(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (map[time.Time]int64, error)
	FirewallGroups(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
	Capabilities(ctx context.Context, zoneID string) (cfapi.Caps, error)
}

// Defaults (constants by design: no new settings).
const (
	DefaultDays = 7
	// MaxQueries is the per-simulation GraphQL budget.
	MaxQueries = 24
	// Settle keeps the window's right edge clear of data still landing.
	Settle = time.Hour
	// CacheTTL: the same simulation within this time is served from cache.
	CacheTTL     = 10 * time.Minute
	topN         = 5
	knownScan    = 50 // user agents scanned for known sources
	maxBranches  = 3  // exemption branches split out one by one
	parallelism  = 4
	botShareWarn = 0.2 // verified bots ≥ 20% of the matches: warn
	tinyShare    = 0.01
	gapRatio     = 0.5 // net new < half of the gross: the gap is the story
	eyeballShare = 0.05
)

// Confidence labels.
const (
	Approx       = "approx"        // sampled data
	ApproxJoined = "approx_joined" // includes the cross-dataset net-new estimate
	UpperBound   = "upper_bound"   // includes widened sub-expressions
)

// Input is one simulation.
type Input struct {
	ZoneID   string
	ZoneName string
	Expr     string
	Action   string // block | challenge
	Days     int    // window length when From/To are zero (default 7)
	From, To time.Time
	Now      time.Time
	// Workers: the zone runs Workers — empty-UA entries (their internal
	// bookkeeping) are left out of every count, and reported apart.
	Workers bool
	// DashRatio is the calibration ratio (FlareHound / dashboard); 0 = none.
	DashRatio float64
	// Known sources (known_faces): user-agent substrings and ASNs.
	KnownUAs  []string
	KnownASNs []int
	// RuleNames labels firewall rule IDs ("handled by").
	RuleNames map[string]string
	// Loc forms the per-day split (default UTC).
	Loc *time.Location

	// Phase 2 context (all optional; without it the report says what it
	// could not take into account).
	// Lists expands $list references (AccountID required).
	Lists     ListAPI
	AccountID string
	// Position: Ahead are the rules that will sit ahead of the draft when
	// the caller knows them (AheadKnown; the block review). Otherwise
	// Rules (the zone's custom rules) or RulesAPI (to read them) place
	// the draft like a new FlareHound rule, or before rule Before (1-based).
	Ahead      []cfapi.Rule
	AheadKnown bool
	Rules      []cfapi.Rule
	RulesAPI   RulesAPI
	Before     int
}

// Branch is one exemption of the expression and what it lets through.
type Branch struct {
	Expr  string `json:"expr"`
	Count int64  `json:"count"`
	Bot   bool   `json:"bot,omitempty"` // the verified-bot exemption
}

// Day is one local day of the matches.
type Day struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
	Part  bool   `json:"part,omitempty"` // the window covers only part of the day
}

// Row is one line of a composition breakdown.
type Row struct {
	Name    string  `json:"name"`
	Count   int64   `json:"count"`
	Share   float64 `json:"share"` // of the matches
	ASN     int     `json:"asn,omitempty"`
	Desc    string  `json:"desc,omitempty"`
	Network string  `json:"network,omitempty"` // ASN rows: hosting | eyeball | unknown
	Country string  `json:"country,omitempty"` // IP rows
	Bot     bool    `json:"bot,omitempty"`     // IP rows: a verified bot
}

// KnownHit is a known source (known_faces) the rule would hit.
type KnownHit struct {
	Pattern string `json:"pattern"`
	Count   int64  `json:"count"`
	ASN     bool   `json:"asn,omitempty"`
}

// Warn is one guard-rail observation (rendered per language).
type Warn struct {
	Code  string  `json:"code"`
	S     string  `json:"s,omitempty"`
	N     int64   `json:"n,omitempty"`
	Share float64 `json:"share,omitempty"`
}

// Warning codes.
const (
	WarnEyeball  = "eyeball"   // a residential/mobile network in the matches
	WarnKnown    = "known"     // a known source is hit
	WarnBots     = "bots"      // verified bots in the matches (no bot exemption)
	WarnTiny     = "tiny"      // net new < 1% of the zone
	WarnGap      = "gap"       // gross ≫ net new
	WarnNoHits   = "no_hits"   // the rule matches nothing
	WarnBlockAll = "block_all" // block: humans who would pass a challenge are blocked too
	WarnChalRate = "chal_rate" // challenge: pass-rate estimate not available yet (phase 2)
	WarnInfix    = "infix"     // infix starts_with/ends_with: not valid in Cloudflare
	WarnSkipped  = "skipped"   // skip rules ahead take a large share of the matches
)

// Report is a simulation's result. It is stored with a block as its
// snapshot, so it holds numbers and codes, not sentences.
type Report struct {
	Zone       string    `json:"zone"`
	ZoneID     string    `json:"zone_id"`
	Expr       string    `json:"expr"`
	Action     string    `json:"action"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	At         time.Time `json:"at"`
	Evaluable  bool      `json:"evaluable"`
	Confidence string    `json:"confidence,omitempty"`
	// Unevaluable sub-expressions (the report has no numbers), and
	// widened ones (the numbers are upper bounds).
	Unevaluable []Item `json:"unevaluable,omitempty"`
	Widened     []Item `json:"widened,omitempty"`

	Total          int64    `json:"total"`   // zone, same cleaning
	Dynamic        int64    `json:"dynamic"` // zone, dynamic (sent to the origin)
	Gross          int64    `json:"gross"`   // without the expression's exemptions
	HasCore        bool     `json:"has_core"`
	Branches       []Branch `json:"branches,omitempty"`
	Exempted       int64    `json:"exempted"`
	Matched        int64    `json:"matched"` // what the rule matches
	MatchedDynamic int64    `json:"matched_dynamic"`
	DynamicKnown   bool     `json:"dynamic_known"`
	EmptyUA        int64    `json:"empty_ua,omitempty"` // left out (Worker bookkeeping)
	CleanEmptyUA   bool     `json:"clean_empty_ua,omitempty"`

	// Net new: the matches minus what existing rules already block or
	// challenge (firewall events, a different dataset: an estimate).
	NetKnown  bool         `json:"net_known"`
	NetWhy    string       `json:"net_why,omitempty"`
	NetFrom   time.Time    `json:"net_from,omitempty"` // net new covers [NetFrom, To) when firewall data is shorter
	NetBase   int64        `json:"net_base,omitempty"` // matches over [NetFrom, To)
	Handled   int64        `json:"handled"`
	HandledBy []cfapi.Face `json:"handled_by,omitempty"`
	Net       int64        `json:"net"`

	Days      []Day      `json:"days,omitempty"`
	Paths     []Row      `json:"paths,omitempty"`
	UAs       []Row      `json:"uas,omitempty"`
	IPs       []Row      `json:"ips,omitempty"`
	Countries []Row      `json:"countries,omitempty"`
	ASNs      []Row      `json:"asns,omitempty"`
	ASNBound  bool       `json:"asn_bound,omitempty"`
	Bots      int64      `json:"bots"`
	BotsKnown bool       `json:"bots_known"`
	Known     []KnownHit `json:"known,omitempty"`

	// Phase 2.
	Lists          []ListUse `json:"lists,omitempty"`
	Position       int       `json:"position,omitempty"` // 1-based, among the custom rules
	PositionKnown  bool      `json:"position_known,omitempty"`
	PositionChosen bool      `json:"position_chosen,omitempty"` // Before was given
	PositionWhy    string    `json:"position_why,omitempty"`
	PosBefore      string    `json:"pos_before,omitempty"` // the rule right after it
	Skips          []SkipRow `json:"skips,omitempty"`      // skip rules ahead that let matches through
	SkippedAhead   int64     `json:"skipped_ahead,omitempty"`
	NetUpper       bool      `json:"net_upper,omitempty"` // a non-logging skip ahead could not be counted
	Chal           Challenge `json:"chal"`

	// Phase 3: partial evaluation. Unknown terms are bounded — counted as
	// matching for the upper bound (every count), as not matching for the
	// lower bound (MatchedLow). Terms annotates each top-level term.
	Partial    bool   `json:"partial,omitempty"`
	Unknown    []Item `json:"unknown,omitempty"`
	MatchedLow int64  `json:"matched_low,omitempty"`
	LowKnown   bool   `json:"low_known,omitempty"`
	Terms      []Term `json:"terms,omitempty"`

	DashRatio float64  `json:"dash_ratio,omitempty"`
	Warnings  []Warn   `json:"warnings,omitempty"`
	Verdict   string   `json:"verdict,omitempty"` // the deciding warning code, or "ok"
	Errors    []string `json:"errors,omitempty"`  // sections that failed
	Queries   int      `json:"queries"`
	Skipped   []string `json:"skipped,omitempty"` // sections left out by the query budget
	Cached    bool     `json:"-"`
}

// Hours is the window length in hours.
func (r *Report) Hours() float64 { return r.To.Sub(r.From).Hours() }

// NetPerDay is the net new per day (over the part of the window it covers).
func (r *Report) NetPerDay() float64 {
	from := r.From
	if !r.NetFrom.IsZero() {
		from = r.NetFrom
	}
	h := r.To.Sub(from).Hours()
	if h <= 0 {
		return 0
	}
	return float64(r.Net) / h * 24
}

// NetPerHour is the prediction the before/after comparison checks.
func (r *Report) NetPerHour() float64 { return r.NetPerDay() / 24 }

// NetShare is the net new's share of the zone's traffic.
func (r *Report) NetShare() float64 {
	if r.Total <= 0 || r.Hours() <= 0 {
		return 0
	}
	return r.NetPerDay() / (float64(r.Total) / r.Hours() * 24)
}

// Share is n's share of the zone's traffic.
func (r *Report) Share(n int64) float64 {
	if r.Total <= 0 {
		return 0
	}
	return float64(n) / float64(r.Total)
}

// DynShare is the matches' share of the zone's dynamic traffic.
func (r *Report) DynShare() float64 {
	if r.Dynamic <= 0 {
		return 0
	}
	return float64(r.MatchedDynamic) / float64(r.Dynamic)
}

// Upper is true when every count is an upper bound (a widened
// sub-expression, or terms bounded by partial evaluation). Net new alone
// can be one too: NetMark.
func (r *Report) Upper() bool { return len(r.Widened) > 0 || r.Partial }

// Window computes the default window: the last `days` days ending an
// hour before now, on the hour (so repeated runs share a cache entry).
func Window(now time.Time, days int) (from, to time.Time) {
	if days <= 0 {
		days = DefaultDays
	}
	to = now.Add(-Settle).UTC().Truncate(time.Hour)
	return to.Add(-time.Duration(days) * 24 * time.Hour), to
}

// Parse checks an expression without querying anything: the parse error,
// or the sub-expressions no plan could evaluate (capability-independent).
func Parse(expr string) (waf.Node, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, errors.New("empty expression")
	}
	if len(expr) > 4096 {
		return nil, errors.New("expression longer than Cloudflare's 4096 characters")
	}
	return waf.Parse(expr)
}

// ErrParse wraps an expression that does not parse.
var ErrParse = errors.New("expression does not parse")

// split separates the top-level exemption branches ("and not X") from the
// rest (the core).
func split(n waf.Node) (core waf.Node, exempt []waf.Node) {
	var conj []waf.Node
	var walk func(waf.Node)
	walk = func(x waf.Node) {
		if a, ok := x.(waf.And); ok {
			walk(a.L)
			walk(a.R)
			return
		}
		conj = append(conj, x)
	}
	walk(n)
	var pos []waf.Node
	for _, c := range conj {
		if nt, ok := c.(waf.Not); ok {
			exempt = append(exempt, nt.X)
		} else {
			pos = append(pos, c)
		}
	}
	if len(exempt) == 0 || len(pos) == 0 {
		return nil, nil
	}
	core = pos[0]
	for _, p := range pos[1:] {
		core = waf.And{L: core, R: p}
	}
	return core, exempt
}

func isBot(n waf.Node) bool {
	t, ok := n.(waf.Truthy)
	if !ok {
		return false
	}
	f, ok := t.X.(waf.Field)
	return ok && f.Name == "cf.client.bot"
}

func hasInfix(n waf.Node) bool {
	found := false
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
			if y.Op == "starts_with" || y.Op == "ends_with" {
				found = true
			}
		}
	}
	walk(n)
	return found
}

// runner executes the query plan within the budget.
type runner struct {
	api    API
	zone   string
	mu     sync.Mutex
	used   int
	r      *Report
	sem    chan struct{}
	wg     sync.WaitGroup
	budget int
}

// take reserves one query; false when the budget is spent.
func (x *runner) take(section string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.used >= x.budget {
		x.r.Skipped = append(x.r.Skipped, section)
		return false
	}
	x.used++
	return true
}

func (x *runner) fail(section string, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.r.Errors = append(x.r.Errors, section+": "+err.Error())
}

// go runs fn concurrently (bounded) when the budget allows.
func (x *runner) do(section string, fn func() error) {
	if !x.take(section) {
		return
	}
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		x.sem <- struct{}{}
		defer func() { <-x.sem }()
		if err := fn(); err != nil {
			x.fail(section, err)
		}
	}()
}

func (x *runner) wait() { x.wg.Wait() }

// Run simulates one expression. A parse error is returned as an error;
// everything else — sub-expressions that cannot be evaluated, sections
// that failed — is in the report.
func Run(ctx context.Context, api API, in Input) (*Report, error) {
	n, err := Parse(in.Expr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.From.IsZero() || in.To.IsZero() {
		in.From, in.To = Window(in.Now, in.Days)
	}
	if in.Action == "" {
		in.Action = "block"
	}
	r := &Report{Zone: in.ZoneName, ZoneID: in.ZoneID, Expr: strings.TrimSpace(in.Expr), Action: in.Action,
		From: in.From.UTC(), To: in.To.UTC(), At: in.Now.UTC(), DashRatio: in.DashRatio}
	x := &runner{api: api, zone: in.ZoneID, r: r, sem: make(chan struct{}, parallelism), budget: MaxQueries}

	x.take("capabilities")
	caps, err := api.Capabilities(ctx, in.ZoneID)
	if err != nil {
		// Probing failed: assume everything, as the watch does; a missing
		// dimension then fails its query and is reported.
		caps = cfapi.AllCaps()
		r.Errors = append(r.Errors, "capabilities: "+err.Error())
	}
	lists, uses := resolveLists(ctx, n, in.Lists, in.AccountID)
	r.Lists = uses
	c := translatePartial(n, caps, lists)
	r.Terms = annotate(n, caps, lists)
	if hasInfix(n) {
		r.Warnings = append(r.Warnings, Warn{Code: WarnInfix})
	}
	if !c.httpOK {
		r.Unevaluable = c.bad
		r.Verdict = "unevaluable"
		r.Queries = x.used
		return r, nil
	}
	r.Evaluable = true
	r.Widened = c.approx
	r.ASNBound = c.asn
	r.Partial, r.Unknown = c.partial, c.unknown
	position(ctx, &in, r)
	labels := ruleLabels(in)

	// Cleaning: the same "real requests" as the reports; on Worker zones
	// the empty-UA bookkeeping entries are left out everywhere.
	clean := gnode{all: true}
	if in.Workers && caps.HasDim(cfapi.DimUserAgent) {
		clean = gnode{leaf: "userAgent_neq:" + q("")}
		r.CleanEmptyUA = true
	}
	httpF := func(g gnode) cfapi.Filter { return cfapi.Filter{Where: where(and(clean, g))} }
	full := c.http
	// fullLow is the lower bound under partial evaluation (full itself
	// otherwise): what is subtracted from net new must be certain, so it
	// is read over the lower bound.
	fullLow, fwLow := c.httpLow, c.fwLow
	from, to := r.From, r.To

	// Required: the zone's total and the matches.
	x.do("total", func() (err error) { r.Total, err = api.Count(ctx, x.zone, from, to, httpF(gnode{all: true})); return })
	x.do("matched", func() (err error) { r.Matched, err = api.Count(ctx, x.zone, from, to, httpF(full)); return })
	if r.Partial && !fullLow.none && !fullLow.all {
		x.do("matched_low", func() (err error) {
			r.MatchedLow, err = api.Count(ctx, x.zone, from, to, httpF(fullLow))
			r.LowKnown = err == nil
			return
		})
	} else if r.Partial && fullLow.none {
		r.LowKnown = true // nothing is certain to match: at least 0
	}
	x.do("dynamic", func() error {
		d, err := api.Count(ctx, x.zone, from, to, cfapi.Filter{CacheStatus: "dynamic", Where: where(clean)})
		r.Dynamic = d
		return err
	})
	x.do("matched_dynamic", func() error {
		d, err := api.Count(ctx, x.zone, from, to, cfapi.Filter{CacheStatus: "dynamic", Where: where(and(clean, full))})
		r.MatchedDynamic, r.DynamicKnown = d, err == nil
		return err
	})

	// Exemptions: the core without its "and not …" branches, and each
	// branch on its own (they may overlap; the total is gross − matched).
	core, exempt := split(n)
	var coreG gnode
	botExempt := false
	// Under partial evaluation the matches are a range; an exemption split
	// on top of it would need ranges of ranges. The term annotations say
	// what each branch is.
	if core != nil && !r.Partial {
		cc := translate(core, caps, lists)
		if cc.httpOK {
			r.HasCore = true
			coreG = cc.http
			x.do("gross", func() (err error) { r.Gross, err = api.Count(ctx, x.zone, from, to, httpF(coreG)); return })
			// The branch list is complete before any query starts: the
			// queries write into it, so it must not grow under them.
			var filters []gnode
			for i, e := range exempt {
				if i >= maxBranches {
					break
				}
				ce := translate(e, caps, lists)
				if !ce.httpOK {
					continue
				}
				b := Branch{Expr: e.String(), Bot: isBot(e)}
				botExempt = botExempt || b.Bot
				r.Branches = append(r.Branches, b)
				filters = append(filters, and(coreG, ce.http))
			}
			for idx, g := range filters {
				x.do("exemption", func() error {
					n, err := api.Count(ctx, x.zone, from, to, httpF(g))
					x.mu.Lock()
					r.Branches[idx].Count = n
					x.mu.Unlock()
					return err
				})
			}
		}
	}
	if !botExempt && caps.HasDim(cfapi.DimVerifiedBot) {
		g := and(full, gnode{leaf: "verifiedBotCategory_neq:" + q("")})
		x.do("verified_bots", func() (err error) {
			r.Bots, err = api.Count(ctx, x.zone, from, to, httpF(g))
			r.BotsKnown = err == nil
			return
		})
	}
	if r.CleanEmptyUA {
		g := and(full, gnode{leaf: "userAgent:" + q("")})
		x.do("empty_ua", func() (err error) {
			r.EmptyUA, err = api.Count(ctx, x.zone, from, to, cfapi.Filter{Where: where(g)})
			return
		})
	}

	// Per day (local days are formed by the caller's location).
	var hourly map[time.Time]int64
	x.do("days", func() (err error) { hourly, err = api.Hourly(ctx, x.zone, from, to, httpF(full)); return })

	// Composition.
	var paths, uas, ips, countries, asns []cfapi.Face
	x.do("paths", func() (err error) {
		paths, err = api.Top(ctx, x.zone, from, to, cfapi.DimPath, topN, httpF(full))
		return
	})
	if caps.HasDim(cfapi.DimUserAgent) {
		x.do("user_agents", func() (err error) {
			uas, err = api.Top(ctx, x.zone, from, to, cfapi.DimUserAgent, knownScan, httpF(full))
			return
		})
	}
	ipDim := caps.ClientIPDim()
	x.do("ips", func() (err error) { ips, err = api.Top(ctx, x.zone, from, to, ipDim, topN*4, httpF(full)); return })
	if caps.HasDim("clientCountryName") {
		x.do("countries", func() (err error) {
			countries, err = api.Top(ctx, x.zone, from, to, "clientCountryName", topN, httpF(full))
			return
		})
	}
	if caps.HasDim(cfapi.DimASN) {
		x.do("asns", func() (err error) {
			asns, err = api.Top(ctx, x.zone, from, to, cfapi.DimASNNamed, topN*2, httpF(full))
			return
		})
	}

	// Net new: what existing rules already stop, from the firewall events.
	var fw []cfapi.Face
	fwFrom := from
	switch {
	case !caps.FirewallEnabled && caps.Probed:
		r.NetWhy = "no_firewall"
	case !c.fwOK:
		r.NetWhy = "firewall_fields"
	default:
		fwFrom = caps.FirewallFrom(from, in.Now)
		if !fwFrom.Before(to) {
			r.NetWhy = "firewall_retention"
			break
		}
		if !fwLow.none { // nothing certain to match: nothing certainly stopped
			fwWhere := where(and(clean, fwLow))
			x.do("handled", func() (err error) {
				fw, err = api.FirewallGroups(ctx, x.zone, fwFrom, to, "action ruleId", 100, cfapi.Filter{Where: fwWhere})
				return
			})
		}
		if fwFrom.After(from) {
			r.NetFrom = fwFrom
			x.do("matched_net", func() (err error) { r.NetBase, err = api.Count(ctx, x.zone, fwFrom, to, httpF(full)); return })
		}
	}
	// Skip rules ahead: logged skips come with the firewall events above;
	// one that logs nothing is counted from its own expression.
	skipPos := skipsAhead(in.Ahead)
	type skipJob struct {
		idx int
		g   gnode
	}
	var skipJobs []skipJob
	if r.NetWhy == "" {
		for i, ar := range in.Ahead {
			if !block.SkipsRest(ar) || ar.Logging == nil || ar.Logging.Enabled {
				continue
			}
			row := SkipRow{Pos: i + 1, Label: block.RuleLabel(ar), NoLog: true}
			sn, err := waf.Parse(ar.Expression)
			var sc compiled
			if err == nil {
				sc = translate(sn, caps, lists)
			}
			if err != nil || !sc.httpOK || len(sc.approx) > 0 || len(r.Skips) >= maxBranches {
				row.Unknown = true
				r.Skips = append(r.Skips, row)
				r.NetUpper = true
				continue
			}
			r.Skips = append(r.Skips, row)
			idx := len(r.Skips) - 1
			g := and(fullLow, sc.http)
			if g.none {
				continue
			}
			skipJobs = append(skipJobs, skipJob{idx: idx, g: g})
		}
		for _, j := range skipJobs {
			x.do("skip_nolog", func() error {
				n, err := api.Count(ctx, x.zone, fwFrom, to, httpF(j.g))
				x.mu.Lock()
				r.Skips[j.idx].Count = n
				x.mu.Unlock()
				return err
			})
		}
	}
	x.wait()
	r.Queries = x.used

	for _, e := range r.Errors {
		if strings.HasPrefix(e, "total:") || strings.HasPrefix(e, "matched:") {
			return r, errors.New(e)
		}
	}

	// Exemptions (a failed gross or branch query drops the split rather
	// than show a made-up zero).
	if r.HasCore && (hasErr(r, "gross") || hasErr(r, "exemption") || contains(r.Skipped, "gross") || contains(r.Skipped, "exemption")) {
		r.HasCore, r.Branches = false, nil
	}
	if r.HasCore {
		if r.Gross < r.Matched { // sampling noise between two queries
			r.Gross = r.Matched
		}
		r.Exempted = r.Gross - r.Matched
	} else {
		r.Gross = r.Matched
	}

	// Net new.
	if r.NetWhy == "" && !hasErr(r, "handled") && !hasErr(r, "matched_net") && !contains(r.Skipped, "handled") {
		base := r.Matched
		if !r.NetFrom.IsZero() {
			base = r.NetBase
		}
		byRule := map[string]int64{}
		skipped := map[string]int64{}
		for _, f := range fw {
			action, rule, _ := strings.Cut(f.Name, " ")
			r.Chal.add(action, f.Count)
			if strings.EqualFold(action, "skip") && skipPos[rule] > 0 {
				skipped[rule] += f.Count
				continue
			}
			if !Mitigating(action) {
				continue
			}
			r.Handled += f.Count
			label := rule
			if nm := labels[rule]; nm != "" {
				label = nm
			}
			byRule[action+" "+label] += f.Count
		}
		for id, n := range skipped {
			pos := skipPos[id]
			r.Skips = append(r.Skips, SkipRow{Pos: pos, Label: block.RuleLabel(in.Ahead[pos-1]), Count: n})
		}
		sort.Slice(r.Skips, func(i, j int) bool { return r.Skips[i].Pos < r.Skips[j].Pos })
		for _, s := range r.Skips {
			r.SkippedAhead += s.Count
		}
		for k, v := range byRule {
			r.HandledBy = append(r.HandledBy, cfapi.Face{Name: k, Count: v})
		}
		sort.Slice(r.HandledBy, func(i, j int) bool { return r.HandledBy[i].Count > r.HandledBy[j].Count })
		if len(r.HandledBy) > topN {
			r.HandledBy = r.HandledBy[:topN]
		}
		r.Net = base - r.Handled - r.SkippedAhead
		if r.Net < 0 {
			r.Net = 0
		}
		r.NetKnown = true
		if r.Partial {
			// upper matches − certainly stopped − certainly skipped: a bound.
			r.NetUpper = true
		}
	} else if r.NetWhy == "" {
		r.NetWhy = "firewall_error"
	}

	// Confidence.
	switch {
	case len(r.Widened) > 0, r.Partial, r.NetKnown && r.NetUpper:
		r.Confidence = UpperBound
	case r.NetKnown:
		r.Confidence = ApproxJoined
	default:
		r.Confidence = Approx
	}

	loc := in.Loc
	if loc == nil {
		loc = time.UTC
	}
	r.Days = foldDays(hourly, r.From, r.To, loc)
	r.Paths = rows(paths, r.Matched, topN)
	r.UAs = rows(uas, r.Matched, topN)
	r.Countries = rows(countries, r.Matched, topN)
	for _, f := range ips {
		if len(r.IPs) >= topN {
			break
		}
		row := Row{Name: f.Name, Count: f.Count, Share: share(f.Count, r.Matched), ASN: f.ASN, Bot: f.Cat != "", Country: geoip.Country(f.Name)}
		r.IPs = append(r.IPs, row)
	}
	for _, f := range asns {
		row := Row{Name: f.Name, Count: f.Count, Share: share(f.Count, r.Matched), ASN: f.ASN, Desc: f.Desc}
		if f.ASN > 0 {
			row.Network = string(suggest.Classify(f.ASN, f.Desc))
		}
		r.ASNs = append(r.ASNs, row)
	}
	r.Known = known(uas, asns, in.KnownUAs, in.KnownASNs)
	judge(r)
	return r, nil
}

func hasErr(r *Report, section string) bool {
	for _, e := range r.Errors {
		if strings.HasPrefix(e, section+":") {
			return true
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Mitigating reports whether a firewall-events action stopped the request
// (blocked it, or issued a challenge). Outcomes of a challenge (solved,
// failed, bypassed) and pass-through actions are not counted, so one
// request is not counted twice.
func Mitigating(action string) bool {
	a := strings.ToLower(strings.ReplaceAll(action, "_", ""))
	switch a {
	case "block", "drop", "connectionclose", "challenge", "jschallenge", "managedchallenge":
		return true
	}
	return false
}

func share(n, of int64) float64 {
	if of <= 0 {
		return 0
	}
	return float64(n) / float64(of)
}

func rows(fs []cfapi.Face, of int64, limit int) []Row {
	var out []Row
	for _, f := range fs {
		if len(out) >= limit {
			break
		}
		out = append(out, Row{Name: f.Name, Count: f.Count, Share: share(f.Count, of), ASN: f.ASN})
	}
	return out
}

// foldDays folds hourly counts into the dates of loc.
func foldDays(h map[time.Time]int64, from, to time.Time, loc *time.Location) []Day {
	if h == nil {
		return nil
	}
	by := map[string]int64{}
	for t, n := range h {
		by[t.In(loc).Format("2006-01-02")] += n
	}
	var out []Day
	for d := from.In(loc); d.Before(to); {
		day := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
		next := day.AddDate(0, 0, 1)
		key := day.Format("2006-01-02")
		out = append(out, Day{Date: key, Count: by[key], Part: day.Before(from) || next.After(to)})
		d = next
	}
	return out
}

// known finds known sources (known_faces) among the matches' user agents
// and networks.
func known(uas, asns []cfapi.Face, patterns []string, knownASNs []int) []KnownHit {
	var out []KnownHit
	for _, p := range patterns {
		lp := strings.ToLower(strings.TrimSpace(p))
		if lp == "" {
			continue
		}
		var n int64
		for _, f := range uas {
			if strings.Contains(strings.ToLower(f.Name), lp) {
				n += f.Count
			}
		}
		if n > 0 {
			out = append(out, KnownHit{Pattern: p, Count: n})
		}
	}
	ka := map[int]bool{}
	for _, a := range knownASNs {
		ka[a] = true
	}
	for _, f := range asns {
		if ka[f.ASN] && f.Count > 0 {
			out = append(out, KnownHit{Pattern: f.Name, Count: f.Count, ASN: true})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// judge applies the guard rails' terms to the numbers: warnings, and the
// one that decides the verdict line.
func judge(r *Report) {
	var w []Warn
	add := func(x Warn) { w = append(w, x) }
	if r.Matched == 0 {
		add(Warn{Code: WarnNoHits})
	}
	for _, a := range r.ASNs {
		if a.Network == string(suggest.Eyeball) && a.Share >= eyeballShare {
			add(Warn{Code: WarnEyeball, S: strings.TrimSpace(a.Name + " " + a.Desc), N: a.Count, Share: a.Share})
		}
	}
	for _, k := range r.Known {
		add(Warn{Code: WarnKnown, S: k.Pattern, N: k.Count})
	}
	if r.BotsKnown && r.Matched > 0 && share(r.Bots, r.Matched) >= botShareWarn {
		add(Warn{Code: WarnBots, N: r.Bots, Share: share(r.Bots, r.Matched)})
	}
	if r.Matched > 0 && r.NetKnown && r.NetShare() < tinyShare {
		add(Warn{Code: WarnTiny, Share: r.NetShare()})
	} else if r.Matched > 0 && !r.NetKnown && r.Share(r.Matched) < tinyShare {
		add(Warn{Code: WarnTiny, Share: r.Share(r.Matched)})
	}
	if r.Gross > 0 && r.NetKnown && float64(r.NetPerDay()) < gapRatio*float64(r.Gross)/r.Hours()*24 {
		add(Warn{Code: WarnGap, N: r.Gross - r.Net, Share: 1 - r.NetPerDay()/(float64(r.Gross)/r.Hours()*24)})
	} else if r.Gross > 0 && !r.NetKnown && float64(r.Matched) < gapRatio*float64(r.Gross) {
		add(Warn{Code: WarnGap, N: r.Exempted, Share: share(r.Exempted, r.Gross)})
	}
	if r.NetKnown && r.Matched > 0 && share(r.SkippedAhead, r.Matched) >= 0.1 {
		add(Warn{Code: WarnSkipped, N: r.SkippedAhead, Share: share(r.SkippedAhead, r.Matched)})
	}
	if r.Action == "challenge" || r.Action == "managed_challenge" {
		add(Warn{Code: WarnChalRate})
	} else {
		add(Warn{Code: WarnBlockAll})
	}
	// Keep an earlier infix note first.
	r.Warnings = append(r.Warnings, w...)
	r.Verdict = "ok"
	for _, code := range []string{WarnNoHits, WarnEyeball, WarnKnown, WarnBots, WarnTiny, WarnGap} {
		for _, x := range r.Warnings {
			if x.Code == code {
				r.Verdict = code
				return
			}
		}
	}
}

// ruleLabels names the zone's rules by ID ("#3 «Protected pages»
// (managed_challenge)"), from the ruleset when known, then rule_names.
func ruleLabels(in Input) map[string]string {
	out := map[string]string{}
	for k, v := range in.RuleNames {
		out[k] = v
	}
	rules := in.Rules
	if rules == nil {
		rules = in.Ahead
	}
	for i, x := range rules {
		if x.ID != "" {
			out[x.ID] = fmt.Sprintf("#%d %s", i+1, block.RuleLabel(x))
		}
	}
	return out
}

// Term statuses.
const (
	TermExact       = "exact"       // evaluated (sampled)
	TermWidened     = "widened"     // evaluated as a superset (the referer's host)
	TermUnknown     = "unknown"     // bounded: matches (upper) / does not (lower)
	TermUnsupported = "unsupported" // a plan gap or an invalid value: no numbers
)

// Term is one top-level term of the expression and how it was evaluated.
type Term struct {
	Expr   string `json:"expr"`
	Status string `json:"status"`
	Items  []Item `json:"items,omitempty"` // why it is not exact
}

// annotate evaluates each top-level term ("a and b and not c") on its own
// and says how it is taken: the term-by-term reading of a mixed
// expression. Nil for a single term that is evaluated exactly.
func annotate(n waf.Node, caps cfapi.Caps, lists map[string]listRes) []Term {
	var conj []waf.Node
	var walk func(waf.Node)
	walk = func(x waf.Node) {
		if a, ok := x.(waf.And); ok {
			walk(a.L)
			walk(a.R)
			return
		}
		conj = append(conj, x)
	}
	walk(n)
	var out []Term
	plain := true
	for _, x := range conj {
		h := &compiler{ds: dsHTTP, caps: caps, lists: lists, partial: true}
		h.compile(x, false)
		t := Term{Expr: x.String(), Status: TermExact}
		switch {
		case len(h.bad) > 0:
			t.Status, t.Items = TermUnsupported, dedupe(h.bad)
		case len(h.unknown) > 0:
			t.Status, t.Items = TermUnknown, dedupe(h.unknown)
		case len(h.approx) > 0:
			t.Status, t.Items = TermWidened, dedupe(h.approx)
		}
		if t.Status != TermExact {
			plain = false
		}
		out = append(out, t)
	}
	if plain {
		return nil
	}
	return out
}
