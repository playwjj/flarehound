// Package blockcli implements the blocking commands (SPEC 13.1):
// block, unblock, blocks (list with attempts) and the TTL enforcer.
// It owns the confirmation flow — show the exact change, the measured
// share, the guard-rail warnings, then ask once — and the audit log.
package blockcli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/store"
	"github.com/playwjj/flarehound/internal/suggest"
)

// ReadAPI is the read-only analytics used for measurement and attempts.
type ReadAPI interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	ASNName(ctx context.Context, zoneID string, from, to time.Time, asn int) (string, error)
	block.FirewallAPI
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

func (e *Env) protected(ctx context.Context, t block.Target, skipOrigin bool) (block.Protected, error) {
	p := block.Protected{Allow: e.Cfg.NeverBlock(), AllowASNs: map[int]bool{}}
	for _, a := range e.Cfg.Blocking.NeverBlockASNs {
		p.AllowASNs[a] = true
	}
	if t.Type != block.IP {
		return p, nil
	}
	if r, err := e.Write.CloudflareRanges(ctx); err == nil && len(r) > 0 {
		p.Cloudflare = r
	} else {
		p.Cloudflare = block.CloudflareFallback()
	}
	origins, err := e.Write.OriginIPs(ctx, e.Zone.ZoneID)
	if err != nil {
		if !skipOrigin {
			return p, fmt.Errorf("cannot read DNS records to protect your origin IPs (%v); grant the write token Zone → DNS: Read, or pass --skip-origin-check if you are sure", err)
		}
		e.printf("warning: origin IPs not checked (%v)\n", err)
	}
	p.Origins = origins
	return p, nil
}

// measure returns the target's share of the last settled hour's excess
// over the same hour yesterday (or of total traffic when there is no
// excess). known is false when the target cannot be measured.
func (e *Env) measure(ctx context.Context, t block.Target) (count int64, share float64, desc string, known bool) {
	f := cfapi.Filter{}
	switch t.Type {
	case block.ASN:
		f.ASN = t.ASNumber()
	case block.UA:
		f.UserAgentLike = "%" + t.Value + "%"
	case block.IP:
		pf, _ := t.Prefix()
		if !pf.IsSingleIP() {
			return 0, 0, "", false
		}
		f.ClientIP = pf.Addr().String()
	default:
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

// Block runs the full confirm-and-apply flow for one target.
func (e *Env) Block(ctx context.Context, t block.Target, o BlockOpts) error {
	if o.Action == "" {
		o.Action = block.DefaultAction(t.Type)
	}
	prot, err := e.protected(ctx, t, o.SkipOriginCheck)
	if err != nil {
		return err
	}
	if err := prot.Check(t); err != nil {
		return fmt.Errorf("refused: %w", err)
	}

	m := e.manager()
	st, err := m.Load(ctx)
	if err != nil {
		return err
	}
	plan, err := st.PlanBlock(t, o.Action)
	if err != nil {
		return err
	}
	if plan.Op == block.OpNone {
		e.printf("%s\n", plan.Note)
		return nil
	}

	network := ""
	label := t.String()
	if t.Type == block.ASN {
		w := schedule.IntradayWindow(e.now(), e.Cfg.IntradayInterval(), e.Cfg.IntradayOffset())
		name, _ := e.Read.ASNName(ctx, e.Zone.ZoneID, w.From.Add(-23*time.Hour), w.To, t.ASNumber())
		network = string(suggest.Classify(t.ASNumber(), name))
		if name != "" {
			label += " (" + name + ")"
		}
		label += " — " + network + " network"
	}
	_, share, measured, known := e.measure(ctx, t)

	e.printf("\nZone:       %s\n", e.Zone.Name)
	e.printf("Target:     %s\n", label)
	e.printf("Action:     %s\n", o.Action)
	e.printf("Mechanism:  %s\n", plan.Note)
	if plan.Expression != "" {
		e.printf("Rule after: %s\n", plan.Expression)
	}
	if known {
		e.printf("Measured:   %s\n", measured)
	} else {
		e.printf("Measured:   not measurable for this target type\n")
	}
	if o.TTL > 0 {
		e.printf("Expires:    %s (after %s; needs `flarehound enforce` running)\n", e.now().Add(o.TTL).In(e.loc()).Format("2006-01-02 15:04 MST"), o.TTL)
	} else {
		e.printf("Expires:    never (unblock with `flarehound unblock %s %s`)\n", t.Type, t.Value)
	}
	for _, w := range block.Warnings(t, o.Action, network, share, known) {
		e.printf("WARNING:    %s\n", w)
	}

	if strong, want := block.NeedsStrongConfirm(t, o.Action, network); strong {
		got := o.Confirm
		if got == "" {
			e.printf("\nThis can block real users. Type %q to confirm: ", want)
			got = e.readLine()
		}
		if !strings.EqualFold(strings.TrimPrefix(strings.ToUpper(got), "AS"), want) {
			return ErrAborted
		}
	} else if !o.Yes {
		e.printf("\nApply? [y/N] ")
		if a := strings.ToLower(e.readLine()); a != "y" && a != "yes" {
			return ErrAborted
		}
	}

	comment := o.Reason
	if comment == "" {
		comment = "manual"
	}
	entry, err := m.Apply(ctx, st, plan, comment)
	if err != nil {
		return err
	}
	ev := store.BlockEvent{At: e.now(), Zone: e.Zone.ZoneID, Op: "block", Type: string(t.Type), Value: t.Value,
		Action: string(o.Action), Mechanism: string(entry.Mechanism), RuleID: entry.RuleID, Reason: o.Reason, Actor: e.Actor}
	if o.TTL > 0 {
		ev.ExpiresAt = e.now().Add(o.TTL)
	}
	if e.Store != nil {
		if err := e.Store.AddBlockEvent(ev); err != nil {
			e.printf("warning: blocked, but the audit record failed: %v\n", err)
		}
	}
	e.printf("Done — %s is now %s (%s, verified by read-back). Undo: %s\n",
		t, map[block.Action]string{block.Block: "blocked", block.Challenge: "challenged"}[o.Action], entry.Mechanism,
		strings.Replace(block.Command(t, block.DefaultAction(t.Type), "", ""), "flarehound block", "flarehound unblock", 1))
	return nil
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
	for _, x := range removed {
		if e.Store != nil {
			if err := e.Store.AddBlockEvent(store.BlockEvent{At: e.now(), Zone: e.Zone.ZoneID, Op: op, Type: string(t.Type), Value: t.Value,
				Action: string(x.Action), Mechanism: string(x.Mechanism), RuleID: x.RuleID, Reason: reason, Actor: e.Actor}); err != nil {
				e.printf("warning: unblocked, but the audit record failed: %v\n", err)
			}
		}
	}
	e.printf("Done — %s removed (verified by read-back).\n", t)
	return nil
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
	tw := tabwriter.NewWriter(e.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "TARGET\tACTION\tMECHANISM\tATTEMPTS %dd\tSINCE\tEXPIRES\tREASON\n", days)
	seen := map[block.Target]bool{}
	for _, x := range block.Sorted(entries) {
		seen[x.Target] = true
		attempts := "n/a"
		if n, err := block.Attempts(ctx, e.Read, e.Zone.ZoneID, x.RuleID, x.Target, from, to); err == nil {
			attempts = fmt.Sprint(n)
		}
		since, expires, reason := "-", "never", "(no audit record: created by hand or elsewhere)"
		if ev, ok := audit[x.Target]; ok {
			since, reason = ev.At.In(e.loc()).Format("2006-01-02 15:04"), ev.Reason
			if !ev.ExpiresAt.IsZero() {
				expires = ev.ExpiresAt.In(e.loc()).Format("2006-01-02 15:04")
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.Target, x.Action, x.Mechanism, attempts, since, expires, reason)
	}
	for t, ev := range audit {
		if !seen[t] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t-\t%s\t-\tMISSING in Cloudflare (removed by hand?)\n", t, ev.Action, ev.Mechanism, ev.At.In(e.loc()).Format("2006-01-02 15:04"))
		}
	}
	return tw.Flush()
}

// Expire removes every block whose TTL has passed and returns how many
// it removed. Blocks already gone from Cloudflare are closed in the
// audit log too.
func (e *Env) Expire(ctx context.Context) (int, error) {
	if e.Store == nil {
		return 0, errors.New("TTL enforcement needs the archive (it holds the expiry times)")
	}
	evs, err := e.Store.ActiveBlocks(e.Zone.ZoneID)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, ev := range evs {
		if ev.ExpiresAt.IsZero() || ev.ExpiresAt.After(e.now()) {
			continue
		}
		t := block.Target{Type: block.Type(ev.Type), Value: ev.Value}
		err := e.Unblock(ctx, t, true, "expire", "TTL reached ("+ev.ExpiresAt.Format(time.RFC3339)+")")
		switch {
		case err == nil:
			n++
		case errors.Is(err, block.ErrNotBlocked):
			n++
		default:
			errs = append(errs, fmt.Errorf("%s: %w", t, err))
		}
	}
	return n, errors.Join(errs...)
}
