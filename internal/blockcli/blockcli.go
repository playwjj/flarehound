// Package blockcli implements the blocking commands (SPEC 13.1):
// block, unblock, blocks (list with attempts) and the TTL enforcer.
// It owns the confirmation flow — show the exact change, the measured
// share, the guard-rail warnings, then ask once — and the audit log.
package blockcli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/calibrate"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/sim"
	"github.com/playwjj/flarehound/internal/store"
	"github.com/playwjj/flarehound/internal/suggest"
)

// ReadAPI is the read-only analytics used for measurement and attempts.
type ReadAPI interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	ASNName(ctx context.Context, zoneID string, from, to time.Time, asn int) (string, error)
	Capabilities(ctx context.Context, zoneID string) (cfapi.Caps, error)
	block.FirewallAPI
	block.MinutesAPI
}

// WriteAPI is the write-token REST surface plus the guard-rail reads.
type WriteAPI interface {
	block.API
	OriginIPs(ctx context.Context, zoneID string) ([]netip.Addr, error)
	CloudflareRanges(ctx context.Context) ([]netip.Prefix, error)
}

type Env struct {
	Cfg   *config.Config
	Zone  config.Zone
	Read  ReadAPI
	Write WriteAPI
	Store *store.Store
	In    io.Reader
	Out   io.Writer
	Now   func() time.Time
	Actor string // recorded in the audit log ("cli", "ttl", …)
	// Sims caches rule simulations (review, then apply); nil: none kept.
	Sims *sim.Cache
	// NoSim turns the review's rule simulation off.
	NoSim bool
	// SimCfg, when set, supplies what the simulation reads from settings
	// that the console can change at run time (known faces, rule names);
	// the console passes its configuration with the settings overlay.
	SimCfg *config.Config

	in *bufio.Reader
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) loc() *time.Location {
	if e.Cfg.Location != nil {
		return e.Cfg.Location
	}
	return time.Local
}

func (e *Env) manager() *block.Manager {
	return &block.Manager{API: e.Write, ZoneID: e.Zone.ZoneID, AccountID: e.Cfg.Cloudflare.AccountID}
}

func (e *Env) printf(format string, a ...any) { fmt.Fprintf(e.Out, format, a...) }

func (e *Env) readLine() string {
	if e.in == nil {
		e.in = bufio.NewReader(e.In)
	}
	s, _ := e.in.ReadString('\n')
	return strings.TrimSpace(s)
}

// ErrAborted is returned when the user declines.
var ErrAborted = errors.New("aborted, nothing changed")

// BlockOpts are the block command's options.
type BlockOpts struct {
	Action          block.Action
	TTL             time.Duration // 0: permanent
	Reason          string
	Yes             bool   // skip the y/N prompt
	Confirm         string // value for strong confirmation without a prompt
	SkipOriginCheck bool
}

func (e *Env) protected(ctx context.Context, t block.Target, skipOrigin bool) (block.Protected, string, error) {
	p := block.Protected{Allow: e.Cfg.NeverBlock(), AllowASNs: map[int]bool{}}
	for _, a := range e.Cfg.Blocking.NeverBlockASNs {
		p.AllowASNs[a] = true
	}
	if t.Type != block.IP {
		return p, "", nil
	}
	if r, err := e.Write.CloudflareRanges(ctx); err == nil && len(r) > 0 {
		p.Cloudflare = r
	} else {
		p.Cloudflare = block.CloudflareFallback()
	}
	origins, err := e.Write.OriginIPs(ctx, e.Zone.ZoneID)
	note := ""
	if err != nil {
		if !skipOrigin {
			return p, "", fmt.Errorf("cannot read DNS records to protect your origin IPs (%v); grant the write token Zone → DNS: Read, or pass --skip-origin-check if you are sure", err)
		}
		note = fmt.Sprintf("origin IPs not checked (%v)", err)
	}
	p.Origins = origins
	return p, note, nil
}

// measure returns the target's share of the last settled hour's excess
// over the same hour yesterday (or of total traffic when there is no
// excess). known is false when the target cannot be measured.
func (e *Env) measure(ctx context.Context, t block.Target) (count int64, share float64, desc string, known bool) {
	f, ok := FilterFor(t)
	if !ok {
		return 0, 0, "", false
	}
	w := schedule.IntradayWindow(e.now(), e.Cfg.IntradayInterval(), e.Cfg.IntradayOffset())
	bw := w.Shift(-24 * time.Hour)
	z := e.Zone.ZoneID
	cur, err1 := e.Read.Count(ctx, z, w.From, w.To, cfapi.Filter{})
	base, err2 := e.Read.Count(ctx, z, bw.From, bw.To, cfapi.Filter{})
	n, err3 := e.Read.Count(ctx, z, w.From, w.To, f)
	if err1 != nil || err2 != nil || err3 != nil || cur == 0 {
		return 0, 0, "", false
	}
	if ex := cur - base; ex > 0 {
		return n, min(float64(n)/float64(ex), 1), fmt.Sprintf("%d requests in %s = %.1f%% of the excess over yesterday (%d → %d)", n, w, min(float64(n)/float64(ex), 1)*100, base, cur), true
	}
	return n, float64(n) / float64(cur), fmt.Sprintf("%d requests in %s = %.1f%% of all traffic (no excess over yesterday)", n, w, float64(n)/float64(cur)*100), true
}

// Prepared is a block ready to confirm: everything the person must see
// before saying yes (SPEC 13.1). The CLI prints it; the console renders
// it. Prepare never changes anything.
type Prepared struct {
	Target     block.Target
	Opts       BlockOpts
	Label      string // target with ASN name and network type
	Network    string // ASN network type: hosting | eyeball | unknown ("" for other types)
	Plan       block.Plan
	Measured   string // the measured share in words ("" when not measurable)
	Share      float64
	ShareKnown bool
	Warnings   []string
	Notes      []string // non-blocking remarks (e.g. origin IPs not checked)
	Strong     bool     // the person must retype StrongWant
	StrongWant string
	ExpiresAt  time.Time // zero: permanent
	// Where is the rule's place in the custom rules after the change, in
	// words ("" for IP Access Rules); Bypass lists skip rules ahead of it
	// that let this target through — the block may then do nothing.
	Where  string
	Bypass []string
	// IP targets: the IP location (country code, "" when the library is
	// off or does not place it) and, for a single address, its network
	// and requests over the last 24 hours. Display only.
	Country   string
	IPASN     int
	IPASNName string
	IPNetwork string // hosting | eyeball | unknown ("" when IPASN is 0)
	Day       int64
	DayKnown  bool
	// Sim is the rule simulation of an expression block (ASN, country,
	// user agent): what the rule this target becomes would have done over
	// the last 7 days. nil for IP blocks, when the read API cannot
	// simulate, or when it failed (SimErr). Not Evaluable: the review
	// falls back to the measured share.
	Sim    *sim.Report
	SimErr string

	state block.State
}

// SimShown reports whether the review shows the simulation in place of
// the single-target measurement.
func (p *Prepared) SimShown() bool { return p.Sim != nil && p.Sim.Evaluable }

// AlreadyDone is true when the target is already blocked as asked.
func (p *Prepared) AlreadyDone() bool { return p.Plan.Op == block.OpNone }

// ConfirmOK checks a typed strong confirmation (case-insensitive, "AS" prefix allowed).
func (p *Prepared) ConfirmOK(typed string) bool {
	if !p.Strong {
		return true
	}
	return strings.EqualFold(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(typed)), "AS"), p.StrongWant)
}

// Prepare runs the guard rails, plans the change and measures the target.
// A guard-rail refusal is returned as an error: there is nothing to confirm.
func (e *Env) Prepare(ctx context.Context, t block.Target, o BlockOpts) (*Prepared, error) {
	if o.Action == "" {
		o.Action = block.DefaultAction(t.Type)
	}
	p := &Prepared{Target: t, Opts: o}
	prot, note, err := e.protected(ctx, t, o.SkipOriginCheck)
	if err != nil {
		return nil, err
	}
	if note != "" {
		p.Notes = append(p.Notes, note)
	}
	if err := prot.Check(t); err != nil {
		return nil, fmt.Errorf("refused: %w", err)
	}
	st, err := e.manager().Load(ctx)
	if err != nil {
		return nil, err
	}
	p.state = st
	if p.Plan, err = st.PlanBlock(t, o.Action); err != nil {
		return nil, err
	}
	if p.AlreadyDone() {
		return p, nil
	}
	p.Label = t.String()
	if t.Type == block.ASN {
		w := schedule.IntradayWindow(e.now(), e.Cfg.IntradayInterval(), e.Cfg.IntradayOffset())
		name, _ := e.Read.ASNName(ctx, e.Zone.ZoneID, w.From.Add(-23*time.Hour), w.To, t.ASNumber())
		p.Network = string(suggest.Classify(t.ASNumber(), name))
		if name != "" {
			p.Label += " (" + name + ")"
		}
		p.Label += " — " + p.Network + " network"
	}
	if t.Type == block.IP {
		p.Country = geoip.Country(t.Value)
		e.ipProfile(ctx, t, p)
	}
	_, p.Share, p.Measured, p.ShareKnown = e.measure(ctx, t)
	if t.Type != block.IP && !e.NoSim {
		p.Sim, p.SimErr = e.Simulate(ctx, block.Expression(t.Type, []string{t.Value}), string(o.Action), 0)
	}
	p.Warnings = block.Warnings(t, o.Action, p.Network, p.Share, p.ShareKnown)
	if !p.Plan.Place.Ignored {
		p.Where = p.Plan.Place.Describe()
		for _, b := range st.Bypasses(t, p.Plan.RuleRef, p.Plan.Place.Pos, e.profile(ctx, t)) {
			p.Bypass = append(p.Bypass, b.String())
		}
	}
	p.Strong, p.StrongWant = block.NeedsStrongConfirm(t, o.Action, p.Network)
	if o.TTL > 0 {
		p.ExpiresAt = e.now().Add(o.TTL)
	}
	return p, nil
}

// SimInput is a simulation of expr on this zone with the zone's cleaning,
// calibration and known sources; days 0 is the default window.
func (e *Env) SimInput(expr, action string, days int) sim.Input {
	c := e.Cfg
	if e.SimCfg != nil {
		c = e.SimCfg
	}
	in := sim.Input{ZoneID: e.Zone.ZoneID, ZoneName: e.Zone.Name, Expr: expr, Action: action, Days: days, Now: e.now(),
		Workers: len(e.Zone.Workers) > 0, Loc: e.loc(), RuleNames: c.RuleNames,
		KnownUAs: c.KnownFaces.UserAgents, KnownASNs: c.KnownFaces.ASNs}
	if e.Store != nil {
		if rows, err := e.Store.CalibrationDays(e.Zone.ZoneID, 7); err == nil {
			in.DashRatio = calibrate.Ratio(rows)
		}
	}
	return in
}

// Simulate runs the rule simulator for expr when the read API can (nil
// report otherwise; a failure is returned as text, never as an error: the
// review goes on without it).
func (e *Env) Simulate(ctx context.Context, expr, action string, days int) (*sim.Report, string) {
	api, ok := e.Read.(sim.API)
	if !ok {
		return nil, ""
	}
	r, err := e.Sims.Run(ctx, api, e.SimInput(expr, action, days))
	if err != nil {
		return nil, err.Error()
	}
	return r, ""
}

// topAPI is the optional Top-N read the bypass check uses for the
// target's user agents.
type topAPI interface {
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
}

// profile returns the target's top user agents over the last 24 hours —
// what the skip rules ahead of the block are evaluated against. Empty when
// the target cannot be selected or the read API has no Top.
func (e *Env) profile(ctx context.Context, t block.Target) []cfapi.Face {
	tp, ok := e.Read.(topAPI)
	if !ok {
		return nil
	}
	f, ok := FilterFor(t)
	if !ok {
		return nil
	}
	to := e.now().UTC().Truncate(time.Minute)
	fs, err := tp.Top(ctx, e.Zone.ZoneID, to.Add(-24*time.Hour), to, cfapi.DimUserAgent, 10, f)
	if err != nil {
		return nil
	}
	return fs
}

// ipProfile fills a single address's network and its requests over the
// last 24 hours (one Top query by ASN, filtered to the address; the name
// best-effort). Left empty when the read API cannot tell.
func (e *Env) ipProfile(ctx context.Context, t block.Target, p *Prepared) {
	tp, ok := e.Read.(topAPI)
	if !ok {
		return
	}
	f, ok := FilterFor(t)
	if !ok {
		return
	}
	to := e.now().UTC().Truncate(time.Minute)
	from := to.Add(-24 * time.Hour)
	fs, err := tp.Top(ctx, e.Zone.ZoneID, from, to, cfapi.DimASN, 3, f)
	if err != nil {
		return
	}
	p.DayKnown = true
	for _, x := range fs {
		p.Day += x.Count
	}
	if len(fs) > 0 && fs[0].ASN > 0 {
		p.IPASN = fs[0].ASN
		p.IPASNName, _ = e.Read.ASNName(ctx, e.Zone.ZoneID, from, to, p.IPASN)
		p.IPNetwork = string(suggest.Classify(p.IPASN, p.IPASNName))
	}
}

// TargetText is a target as text, an IP target followed by its IP
// location: "203.0.113.7 [IN · India]".
func TargetText(t block.Target, lang string) string {
	if t.Type == block.IP {
		return t.String() + geoip.Suffix(t.Value, lang)
	}
	return t.String()
}

// Execute applies a prepared block (verified by read-back) and appends
// the audit record. Confirmation is the caller's job.
func (e *Env) Execute(ctx context.Context, p *Prepared) (block.Entry, error) {
	comment := p.Opts.Reason
	if comment == "" {
		comment = "manual"
	}
	entry, err := e.manager().Apply(ctx, p.state, p.Plan, comment)
	if err != nil {
		return entry, err
	}
	if want := p.Plan.Place; !want.Ignored && entry.Pos > 0 && entry.Pos != want.Pos {
		p.Notes = append(p.Notes, fmt.Sprintf("read-back: rule %s is at #%d, expected #%d — the block is live; check the order in the dashboard", p.Plan.RuleRef, entry.Pos, want.Pos))
	}
	ev := store.BlockEvent{At: e.now(), Zone: e.Zone.ZoneID, Op: "block", Type: string(p.Target.Type), Value: p.Target.Value,
		Action: string(p.Opts.Action), Mechanism: string(entry.Mechanism), RuleID: entry.RuleID, Reason: p.Opts.Reason,
		ExpiresAt: p.ExpiresAt, Actor: e.Actor}
	if e.Store != nil {
		// The simulation the person saw is kept with the record, so the
		// before/after comparison can set "predicted" against "actual".
		var snap []byte
		if p.SimShown() {
			snap, _ = json.Marshal(p.Sim)
		}
		if err := e.Store.AddBlockEventSim(ev, snap); err != nil {
			return entry, fmt.Errorf("%w: %v", ErrAuditFailed, err)
		}
	}
	return entry, nil
}

// ErrAuditFailed: the change was made but its audit record was not written.
var ErrAuditFailed = errors.New("applied, but the audit record failed")

// FilterFor is the analytics filter selecting a target's requests. CIDRs
// and countries cannot be selected in adaptive analytics (ok is false).
func FilterFor(t block.Target) (cfapi.Filter, bool) { return block.AnalyticsFilter(t) }

// ApproxAttempts approximates a block's attempts in [from, to) from the
// archived IP board (zones without firewall events). ok is false when the
// target is not an IP or there is no archive.
func (e *Env) ApproxAttempts(t block.Target, from, to time.Time) (block.Approx, bool, error) {
	if e.Store == nil || t.Type != block.IP {
		return block.Approx{}, false, nil
	}
	hs, err := e.Store.HourSnapshots(e.Zone.ZoneID, from, to)
	if err != nil {
		return block.Approx{}, false, err
	}
	hf := make([]block.HourFaces, 0, len(hs))
	for _, h := range hs {
		hf = append(hf, block.HourFaces{From: h.From, Faces: h.BlockedIPs})
	}
	a, ok := block.ApproxAttempts(t, hf)
	return a, ok, nil
}

// LiveCheck runs the live check for one block (see block.LiveCheck).
func (e *Env) LiveCheck(ctx context.Context, x block.Entry, caps cfapi.Caps) (block.Live, bool, error) {
	firewall := !caps.Probed || caps.FirewallEnabled
	return block.LiveCheck(ctx, e.Read, e.Zone.ZoneID, x.RuleID, x.Target, firewall, e.now())
}

// LiveText renders a live check for the CLI: a count with the last
// attempt, an empty hour with the last attempt before it, or nothing in
// the look-back — never a bare 0 — plus how far firewall data reaches.
func LiveText(l block.Live, now time.Time, loc *time.Location) string {
	var s string
	switch {
	case l.Count > 0:
		s = fmt.Sprintf("%d (last %s)", l.Count, l.Last.In(loc).Format("15:04"))
	case !l.Last.IsZero():
		s = fmt.Sprintf("none landed yet; last %s (%s ago)", l.Last.In(loc).Format("15:04"), now.Sub(l.Last).Round(time.Minute))
	default:
		s = fmt.Sprintf("none in %s", block.LiveLookback)
	}
	if !l.Frontier.IsZero() {
		s += ", data to " + l.Frontier.In(loc).Format("15:04")
	}
	return s
}

// Live loads the zone's FlareHound blocks as Cloudflare holds them.
func (e *Env) Live(ctx context.Context) (block.State, []block.Entry, error) {
	st, err := e.manager().Load(ctx)
	if err != nil {
		return st, nil, err
	}
	es, err := st.Entries()
	return st, block.Sorted(es), err
}

// Block runs the full confirm-and-apply flow for one target.
func (e *Env) Block(ctx context.Context, t block.Target, o BlockOpts) error {
	p, err := e.Prepare(ctx, t, o)
	if err != nil {
		return err
	}
	for _, n := range p.Notes {
		e.printf("warning: %s\n", n)
	}
	if p.AlreadyDone() {
		e.printf("%s\n", p.Plan.Note)
		return nil
	}
	o = p.Opts
	e.printf("\nZone:       %s\n", e.Zone.Name)
	e.printf("Target:     %s\n", p.Label)
	e.printf("Action:     %s\n", o.Action)
	e.printf("Mechanism:  %s\n", p.Plan.Note)
	if p.Plan.Expression != "" {
		e.printf("Rule after: %s\n", p.Plan.Expression)
	}
	if p.Where != "" {
		e.printf("Position:   rule %s %s\n", p.Plan.RuleRef, p.Where)
	}
	if t.Type == block.IP {
		if loc := geoip.Label(p.Country, "en"); loc != "" {
			e.printf("IP location: %s (registered/routed location, not the operator's; reference only)\n", loc)
		}
		if p.IPASN > 0 {
			name := ""
			if p.IPASNName != "" {
				name = " (" + p.IPASNName + ")"
			}
			e.printf("Network:    AS%d%s — %s network\n", p.IPASN, name, p.IPNetwork)
		}
		if p.DayKnown {
			e.printf("Last 24 h:  %d requests\n", p.Day)
		}
	}
	switch {
	case p.SimShown():
		e.printf("Simulated:  %s\n", p.Sim.VerdictText(e.Cfg.Report.Language))
		e.printf("            %s · last %.0f days · `flarehound simulate --expr '%s'` for the full report\n",
			sim.LabelText(p.Sim.Confidence, e.Cfg.Report.Language), p.Sim.Hours()/24, block.Expression(t.Type, []string{t.Value}))
	case p.ShareKnown:
		e.printf("Measured:   %s\n", p.Measured)
	default:
		e.printf("Measured:   not measurable for this target type\n")
	}
	if o.TTL > 0 {
		e.printf("Expires:    %s (after %s; lifted by the console holding the write token, or by `flarehound enforce`)\n", p.ExpiresAt.In(e.loc()).Format("2006-01-02 15:04 MST"), o.TTL)
	} else {
		e.printf("Expires:    never (unblock with `flarehound unblock %s %s`)\n", t.Type, t.Value)
	}
	for _, w := range p.Warnings {
		e.printf("WARNING:    %s\n", w)
	}
	for _, b := range p.Bypass {
		e.printf("WARNING:    %s\n", b)
	}

	if p.Strong {
		got := o.Confirm
		if got == "" {
			e.printf("\nThis can block real users. Type %q to confirm: ", p.StrongWant)
			got = e.readLine()
		}
		if !p.ConfirmOK(got) {
			return ErrAborted
		}
	} else if !o.Yes {
		e.printf("\nApply? [y/N] ")
		if a := strings.ToLower(e.readLine()); a != "y" && a != "yes" {
			return ErrAborted
		}
	}

	notes := len(p.Notes)
	entry, err := e.Execute(ctx, p)
	if errors.Is(err, ErrAuditFailed) {
		e.printf("warning: %v\n", err)
	} else if err != nil {
		return err
	}
	for _, n := range p.Notes[notes:] {
		e.printf("warning: %s\n", n)
	}
	e.printf("Done — %s is now %s (%s, verified by read-back). Undo: %s\n",
		t, map[block.Action]string{block.Block: "blocked", block.Challenge: "challenged"}[o.Action], entry.Mechanism,
		strings.Replace(block.Command(t, block.DefaultAction(t.Type), "", ""), "flarehound block", "flarehound unblock", 1))
	return nil
}

// Current returns how a target is blocked in Cloudflare right now.
func (e *Env) Current(ctx context.Context, t block.Target) ([]block.Entry, error) {
	st, err := e.manager().Load(ctx)
	if err != nil {
		return nil, err
	}
	return st.Find(t)
}

// Unblock removes a target. op is "unblock" or "expire".
func (e *Env) Unblock(ctx context.Context, t block.Target, yes bool, op, reason string) error {
	m := e.manager()
	st, err := m.Load(ctx)
	if err != nil {
		return err
	}
	es, err := st.Find(t)
	if err != nil {
		return err
	}
	if len(es) == 0 {
		if op == "expire" && e.Store != nil {
			_ = e.Store.AddBlockEvent(store.BlockEvent{At: e.now(), Zone: e.Zone.ZoneID, Op: op, Type: string(t.Type), Value: t.Value,
				Reason: "already absent in Cloudflare", Actor: e.Actor})
		}
		return fmt.Errorf("%s: %w", t, block.ErrNotBlocked)
	}
	if !yes {
		for _, x := range es {
			e.printf("%s: %s via %s\n", t, x.Action, x.Mechanism)
		}
		e.printf("Remove? [y/N] ")
		if a := strings.ToLower(e.readLine()); a != "y" && a != "yes" {
			return ErrAborted
		}
	}
	removed, err := m.Unblock(ctx, st, t)
	if err != nil {
		return err
	}
	var auditErr error
	for _, x := range removed {
		if e.Store != nil {
			if err := e.Store.AddBlockEvent(store.BlockEvent{At: e.now(), Zone: e.Zone.ZoneID, Op: op, Type: string(t.Type), Value: t.Value,
				Action: string(x.Action), Mechanism: string(x.Mechanism), RuleID: x.RuleID, Reason: reason, Actor: e.Actor}); err != nil {
				e.printf("warning: unblocked, but the audit record failed: %v\n", err)
				auditErr = fmt.Errorf("%w: %v", ErrAuditFailed, err)
			}
		}
	}
	e.printf("Done — %s removed (verified by read-back).\n", t)
	return auditErr
}

// Renew changes the expiry of an active block (zero: permanent). Only
// the audit log changes: expiry is FlareHound's, Cloudflare has no TTL.
func (e *Env) Renew(ctx context.Context, t block.Target, expires time.Time, reason string) (store.BlockEvent, error) {
	if e.Store == nil {
		return store.BlockEvent{}, errors.New("expiry times live in the archive, which is disabled")
	}
	es, err := e.Current(ctx, t)
	if err != nil {
		return store.BlockEvent{}, err
	}
	if len(es) == 0 {
		return store.BlockEvent{}, fmt.Errorf("%s: %w", t, block.ErrNotBlocked)
	}
	ev := store.BlockEvent{At: e.now(), Zone: e.Zone.ZoneID, Op: "renew", Type: string(t.Type), Value: t.Value,
		Action: string(es[0].Action), Mechanism: string(es[0].Mechanism), RuleID: es[0].RuleID, Reason: reason, ExpiresAt: expires, Actor: e.Actor}
	return ev, e.Store.AddBlockEvent(ev)
}

// List prints every FlareHound block in the zone with its attempts over
// the last `days` days, reconciled against the audit log.
func (e *Env) List(ctx context.Context, days int) error {
	st, err := e.manager().Load(ctx)
	if err != nil {
		return err
	}
	entries, err := st.Entries()
	if err != nil {
		return err
	}
	audit := map[block.Target]store.BlockEvent{}
	if e.Store != nil {
		evs, err := e.Store.ActiveBlocks(e.Zone.ZoneID)
		if err != nil {
			return err
		}
		for _, ev := range evs {
			audit[block.Target{Type: block.Type(ev.Type), Value: ev.Value}] = ev
		}
	}
	e.printf("Zone %s — custom rules in use %d of %d (%s plan); times in %s\n", e.Zone.Name, st.RulesUsed(), st.RuleLimit(), st.Plan, e.loc())
	if st.NoLists || st.NoAccess {
		e.printf("note: the write token cannot read IP lists (%v) / IP Access Rules (%v); blocks held there are not shown\n", st.NoLists, st.NoAccess)
	}
	e.printf("\n")
	if len(entries) == 0 && len(audit) == 0 {
		e.printf("No FlareHound blocks.\n")
		return nil
	}
	to := e.now().UTC().Truncate(time.Hour)
	from := to.Add(-time.Duration(days) * 24 * time.Hour)
	caps, _ := e.Read.Capabilities(ctx, e.Zone.ZoneID)
	attemptsNA := caps.Probed && !caps.FirewallEnabled
	if c := caps.FirewallFrom(from, e.now()); c.After(from) {
		from = c
		e.printf("note: attempts cover only %.0f day(s) — the zone keeps firewall events that long\n", to.Sub(from).Hours()/24)
	}
	if attemptsNA {
		e.printf("note: no firewall events on this plan — IP attempts are approximated from the archived IP board (~: Top 50 per hour, so low-volume knocking may read 0; \"last\" is the last hour the IP made the list)\n")
	}
	e.printf("LIVE = the last hour, queried now (%s); \"last\" looks back %s\n", map[bool]string{true: "requests stopped at the edge, any rule",
		false: "firewall events on the block's rule — they can reach the dataset 30–60 min late, \"data to\" says how far they go"}[attemptsNA], block.LiveLookback)
	tw := tabwriter.NewWriter(e.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "TARGET\tACTION\tMECHANISM\tATTEMPTS %dd\tLIVE 1h\tSINCE\tEXPIRES\tREASON\n", days)
	seen := map[block.Target]bool{}
	for _, x := range block.Sorted(entries) {
		seen[x.Target] = true
		attempts := "n/a"
		if !attemptsNA {
			if n, err := block.Attempts(ctx, e.Read, e.Zone.ZoneID, x.RuleID, x.Target, from, to); err == nil {
				attempts = fmt.Sprint(n)
			}
		} else if a, ok, err := e.ApproxAttempts(x.Target, from, to); err == nil && ok && a.Hours > 0 {
			attempts = "~" + fmt.Sprint(a.Count)
			if !a.LastHour.IsZero() {
				attempts += " (last " + a.LastHour.In(e.loc()).Format("01-02 15h") + ")"
			}
		}
		live := "-"
		if l, ok, err := e.LiveCheck(ctx, x, caps); err != nil {
			live = "error"
		} else if ok {
			live = LiveText(l, e.now(), e.loc())
		}
		since, expires, reason := "-", "never", "(no audit record: created by hand or elsewhere)"
		if ev, ok := audit[x.Target]; ok {
			since, reason = ev.At.In(e.loc()).Format("2006-01-02 15:04"), ev.Reason
			if !ev.ExpiresAt.IsZero() {
				expires = ev.ExpiresAt.In(e.loc()).Format("2006-01-02 15:04")
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", TargetText(x.Target, "en"), x.Action, x.Mechanism, attempts, live, since, expires, reason)
	}
	for t, ev := range audit {
		if !seen[t] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t-\t-\t%s\t-\tMISSING in Cloudflare (removed by hand?)\n", TargetText(t, "en"), ev.Action, ev.Mechanism, ev.At.In(e.loc()).Format("2006-01-02 15:04"))
		}
	}
	return tw.Flush()
}

// Expire removes every block whose TTL has passed and returns how many
// it removed. Blocks already gone from Cloudflare are closed in the
// audit log too.
func (e *Env) Expire(ctx context.Context) (int, error) {
	ts, err := e.ExpireTargets(ctx)
	return len(ts), err
}

// ExpireTargets is Expire returning the targets it closed.
func (e *Env) ExpireTargets(ctx context.Context) ([]block.Target, error) {
	if e.Store == nil {
		return nil, errors.New("TTL enforcement needs the archive (it holds the expiry times)")
	}
	evs, err := e.Store.ActiveBlocks(e.Zone.ZoneID)
	if err != nil {
		return nil, err
	}
	var done []block.Target
	var errs []error
	for _, ev := range evs {
		if ev.ExpiresAt.IsZero() || ev.ExpiresAt.After(e.now()) {
			continue
		}
		t := block.Target{Type: block.Type(ev.Type), Value: ev.Value}
		err := e.Unblock(ctx, t, true, "expire", "TTL reached ("+ev.ExpiresAt.Format(time.RFC3339)+")")
		switch {
		case err == nil, errors.Is(err, block.ErrNotBlocked), errors.Is(err, ErrAuditFailed):
			done = append(done, t)
		default:
			errs = append(errs, fmt.Errorf("%s: %w", t, err))
		}
	}
	return done, errors.Join(errs...)
}
