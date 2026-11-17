// Package check is the CheckRunner of SPEC 5: it fetches both windows,
// runs the detection engine, follows up with attribution queries when
// something fired, advances the state machine and hands the result to
// the report and notify layers.
package check

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/state"
)

// API is the subset of the Cloudflare client the runner needs.
type API interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
	FirewallByRule(ctx context.Context, zoneID string, from, to time.Time, limit int) ([]cfapi.Face, error)
	WorkerStats(ctx context.Context, accountID, script string, from, to time.Time) (int64, float64, error)
}

// Sender delivers a rendered message.
type Sender interface {
	Send(ctx context.Context, text string) error
}

type Runner struct {
	API    API
	Cfg    *config.Config
	Sender Sender
	Now    func() time.Time                                 // default time.Now
	Sleep  func(ctx context.Context, d time.Duration) error // default: timer
}

const (
	currentTop  = 10 // Top N of the current window (SPEC 6.5)
	baselineTop = 25 // "old faces" list
	settleGrow  = 0.02
)

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Thresholds converts config thresholds into the engine's form.
func Thresholds(cfg *config.Config) analyze.Thresholds {
	t := cfg.Thresholds
	th := analyze.Thresholds{
		TotalUpPct:         t.TotalUpPct,
		WorkerCallsUpPct:   t.WorkerCallsUpPct,
		CPUP50UpPct:        t.CPUP50UpPct,
		DynamicUpPct:       t.DynamicUpPct,
		Origin5xxMultiple:  t.Origin5xxMultiple,
		Origin5xxMin:       t.Origin5xxMin,
		NewFaceMinCount:    t.NewFaceMinCount,
		CollapseDownPct:    t.CollapseDownPct,
		MinCount:           t.MinCount,
		EscalationPct:      t.EscalationPct,
		RecoveryCleanRound: t.RecoveryCleanRound,
	}
	for _, p := range cfg.PathRules {
		up, mc := p.UpPct, p.MinCount
		if up == 0 {
			up = 100
		}
		if mc == 0 {
			mc = 20
		}
		th.PathRules = append(th.PathRules, analyze.PathRule{Name: p.Name, UpPct: up, MinCount: mc})
	}
	return th
}

func known(cfg *config.Config) analyze.Known {
	k := analyze.Known{ASNs: map[int]bool{}, UserAgents: cfg.KnownFaces.UserAgents}
	for _, a := range cfg.KnownFaces.ASNs {
		k.ASNs[a] = true
	}
	return k
}

// like turns a config path pattern ("/login*") into a GraphQL like
// pattern ("/login%").
func like(p string) string { return strings.ReplaceAll(p, "*", "%") }

// StatePath derives a per-zone state file when several zones are
// watched, so their anomaly state machines never mix.
func StatePath(cfg *config.Config, zone config.Zone) string {
	if len(cfg.Cloudflare.Zones) <= 1 {
		return cfg.StateFile
	}
	slug := strings.NewReplacer(".", "-", "/", "-", string(filepath.Separator), "-").Replace(zone.Name)
	return strings.TrimSuffix(cfg.StateFile, ".json") + "-" + slug + ".json"
}

func (r *Runner) fetch(ctx context.Context, zone config.Zone, w schedule.Window, top int) (analyze.Metrics, error) {
	var m analyze.Metrics
	var err error
	z, from, to := zone.ZoneID, w.From, w.To
	if m.Total, err = r.API.Count(ctx, z, from, to, cfapi.Filter{}); err != nil {
		return m, fmt.Errorf("total: %w", err)
	}
	if m.Dynamic, err = r.API.Count(ctx, z, from, to, cfapi.Filter{CacheStatus: "dynamic"}); err != nil {
		return m, fmt.Errorf("dynamic: %w", err)
	}
	if m.Origin5xx, err = r.API.Count(ctx, z, from, to, cfapi.Filter{OriginStatusFrom: 500, OriginStatusTo: 600}); err != nil {
		return m, fmt.Errorf("origin 5xx: %w", err)
	}
	if m.TopUA, err = r.API.Top(ctx, z, from, to, cfapi.DimUserAgent, top, cfapi.Filter{}); err != nil {
		return m, fmt.Errorf("top UA: %w", err)
	}
	if m.TopASN, err = r.API.Top(ctx, z, from, to, cfapi.DimASN, top, cfapi.Filter{}); err != nil {
		return m, fmt.Errorf("top ASN: %w", err)
	}
	for _, name := range zone.Workers {
		calls, cpu, err := r.API.WorkerStats(ctx, r.Cfg.Cloudflare.AccountID, name, from, to)
		if err != nil {
			return m, fmt.Errorf("worker %s: %w", name, err)
		}
		m.Workers = append(m.Workers, analyze.WorkerMetrics{Name: name, Calls: calls, CPUP50ms: cpu})
	}
	for _, p := range r.Cfg.PathRules {
		n, err := r.API.Count(ctx, z, from, to, cfapi.Filter{PathLike: like(p.Path)})
		if err != nil {
			return m, fmt.Errorf("path %s: %w", p.Name, err)
		}
		if m.Paths == nil {
			m.Paths = map[string]int64{}
		}
		m.Paths[p.Name] = n
	}
	return m, nil
}

// verifyBots drops new-face UA findings whose crawler claim is backed by
// the crawler's own ASNs (SPEC 7.3), returning what it verified.
func (r *Runner) verifyBots(ctx context.Context, zone config.Zone, w schedule.Window, fs []analyze.Finding) ([]analyze.Finding, []string) {
	var out []analyze.Finding
	var verified []string
	for _, f := range fs {
		if f.Rule == analyze.RuleNewFaceUA {
			if _, _, claims := analyze.ClaimedBot(f.Subject); claims {
				asns, err := r.API.Top(ctx, zone.ZoneID, w.From, w.To, cfapi.DimASN, 5, cfapi.Filter{UserAgent: f.Subject})
				if err != nil {
					log.Printf("zone %s: verify bot: %v", zone.Name, err)
				} else if name, ok := analyze.VerifiedBot(f.Subject, asns); ok {
					verified = append(verified, name)
					continue
				}
			}
		}
		out = append(out, f)
	}
	return out, verified
}

// settle re-reads windows that look collapsed. If the count is still
// growing, the "collapse" is ingestion lag: the finding is withheld and
// noted as unsettled instead of alerted (SPEC 6).
func (r *Runner) settle(ctx context.Context, zone config.Zone, w schedule.Window, cur *analyze.Metrics, fs []analyze.Finding) ([]analyze.Finding, []string, error) {
	if !analyze.HasCollapse(fs) {
		return fs, nil, nil
	}
	if err := r.sleep(ctx, r.Cfg.SettleDelay()); err != nil {
		return fs, nil, err
	}
	grew := func(before, after int64) bool { return float64(after) > float64(before)*(1+settleGrow) }
	var out []analyze.Finding
	var unsettled []string
	for _, f := range fs {
		switch f.Rule {
		case analyze.RuleCollapseTotal:
			n, err := r.API.Count(ctx, zone.ZoneID, w.From, w.To, cfapi.Filter{})
			if err != nil {
				return fs, nil, err
			}
			if grew(cur.Total, n) {
				unsettled = append(unsettled, f.Key())
				cur.Total = n
				continue
			}
		case analyze.RuleCollapseWorker:
			n, _, err := r.API.WorkerStats(ctx, r.Cfg.Cloudflare.AccountID, f.Subject, w.From, w.To)
			if err != nil {
				return fs, nil, err
			}
			if grew(int64(f.Cur), n) {
				unsettled = append(unsettled, f.Key())
				continue
			}
		}
		out = append(out, f)
	}
	return out, unsettled, nil
}

// attribute runs the follow-up queries of SPEC 6.6 / 8. Failures degrade
// the attribution instead of failing the round: an alert with partial
// evidence beats no alert.
func (r *Runner) attribute(ctx context.Context, zone config.Zone, w, bw schedule.Window, fs []analyze.Finding, a *analyze.Attribution) {
	z := zone.ZoneID
	logErr := func(what string, err error) {
		if err != nil {
			log.Printf("zone %s: attribution %s: %v", zone.Name, what, err)
		}
	}
	var err error
	a.CacheCur, err = r.API.Top(ctx, z, w.From, w.To, cfapi.DimCacheStatus, 20, cfapi.Filter{})
	logErr("cache status", err)
	a.CacheBase, err = r.API.Top(ctx, z, bw.From, bw.To, cfapi.DimCacheStatus, 20, cfapi.Filter{})
	logErr("cache status (baseline)", err)

	a.DynamicPaths, err = r.pathDeltas(ctx, z, w, bw, 5)
	logErr("dynamic paths", err)

	a.TopIPs, err = r.API.Top(ctx, z, w.From, w.To, cfapi.DimClientIP, 5, cfapi.Filter{})
	logErr("top IPs", err)

	for _, f := range fs {
		var flt cfapi.Filter
		switch f.Rule {
		case analyze.RuleNewFaceUA:
			flt.UserAgent = f.Subject
		case analyze.RuleNewFaceASN:
			flt.ASN = f.ASN
		default:
			continue
		}
		paths, err := r.API.Top(ctx, z, w.From, w.To, cfapi.DimPath, 3, flt)
		logErr("face paths", err)
		if len(paths) > 0 {
			if a.FacePaths == nil {
				a.FacePaths = map[string][]cfapi.Face{}
			}
			a.FacePaths[f.Subject] = paths
		}
	}

	a.Firewall, err = r.API.FirewallByRule(ctx, z, w.From, w.To, 10)
	if err != nil {
		a.FirewallNA = true
		log.Printf("zone %s: firewall events unavailable: %v", zone.Name, err)
	}
}

// pathDeltas returns the current window's top dynamic paths with their
// baseline counts. Missing from the baseline Top 25 reads as 0 — which,
// under sampling, means "small", not "absent" (SPEC 6).
func (r *Runner) pathDeltas(ctx context.Context, z string, w, bw schedule.Window, n int) ([]analyze.PathDelta, error) {
	dyn := cfapi.Filter{CacheStatus: "dynamic"}
	cur, err := r.API.Top(ctx, z, w.From, w.To, cfapi.DimPath, n, dyn)
	if err != nil {
		return nil, err
	}
	base, err := r.API.Top(ctx, z, bw.From, bw.To, cfapi.DimPath, baselineTop, dyn)
	if err != nil {
		return nil, err
	}
	bm := map[string]int64{}
	for _, b := range base {
		bm[b.Name] = b.Count
	}
	out := make([]analyze.PathDelta, 0, len(cur))
	for _, c := range cur {
		out = append(out, analyze.PathDelta{Path: c.Name, Cur: c.Count, Base: bm[c.Name]})
	}
	return out, nil
}

// Intraday runs one watch round for a zone: the newest settled interval
// against the same interval yesterday.
func (r *Runner) Intraday(ctx context.Context, zone config.Zone) error {
	cfg := r.Cfg
	w := schedule.IntradayWindow(r.now(), cfg.IntradayInterval(), cfg.IntradayOffset())
	bw := w.Shift(-24 * time.Hour)

	sp := StatePath(cfg, zone)
	st, err := state.Load(sp)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if !st.LastWindow.IsZero() && !w.To.After(st.LastWindow) {
		log.Printf("zone %s: window %s already evaluated, skipping", zone.Name, w)
		return nil
	}

	cur, err := r.fetch(ctx, zone, w, currentTop)
	if err != nil {
		return err
	}
	base, err := r.fetch(ctx, zone, bw, baselineTop)
	if err != nil {
		return err
	}

	th := Thresholds(cfg)
	findings := analyze.Evaluate(cur, base, th, known(cfg))
	var attr analyze.Attribution
	findings, attr.VerifiedBots = r.verifyBots(ctx, zone, w, findings)
	findings, attr.Unsettled, err = r.settle(ctx, zone, w, &cur, findings)
	if err != nil {
		return err
	}

	firstAlert := st.FirstAlertAt
	decision := state.Decide(st, findings, th.EscalationPct, th.RecoveryCleanRound, r.now())
	st.LastWindow = w.To

	for _, f := range findings {
		log.Printf("zone %s: finding %s", zone.Name, f)
	}
	for _, u := range attr.Unsettled {
		log.Printf("zone %s: %s withheld: window still filling after settle delay", zone.Name, u)
	}

	var text string
	if decision.Notify() {
		if decision != state.DecRecovered {
			r.attribute(ctx, zone, w, bw, findings, &attr)
			firstAlert = st.FirstAlertAt
		}
		text = report.Intraday(cfg.Report.Language, report.IntradayData{
			Zone: zone.Name, Window: w, Loc: cfg.Location, Decision: decision,
			Cur: cur, Base: base, Findings: findings, Attr: attr,
			Hypotheses: analyze.Hypothesize(cur, base, findings, attr),
			Block:      analyze.Block(cur, base, attr),
			Since:      firstAlert,
		})
	}

	// State first: if delivery fails the message is already in the
	// outbox, and the episode must not re-alert next round.
	if err := st.Save(sp); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if text == "" {
		log.Printf("zone %s: %s quiet (findings=%d, active=%v)", zone.Name, w, len(findings), st.Active)
		return nil
	}
	log.Printf("zone %s: %s decision=%s findings=%d", zone.Name, w, decision, len(findings))
	return r.Sender.Send(ctx, text)
}

// Daily builds and sends the daily report (SPEC 7.1 / 7.4): the last
// 24 hours against the 24 hours before, with fixed checkpoints. It is
// a scheduled report, so it is always sent; problems expand, a clean
// day stays short.
func (r *Runner) Daily(ctx context.Context, zone config.Zone) error {
	cfg := r.Cfg
	w, err := schedule.DailyWindow(r.now(), cfg.Schedule.DailyReportAt, cfg.Location, cfg.IntradayOffset())
	if err != nil {
		return err
	}
	bw := w.Shift(-24 * time.Hour)
	z := zone.ZoneID

	cur, err := r.fetch(ctx, zone, w, currentTop)
	if err != nil {
		return err
	}
	base, err := r.fetch(ctx, zone, bw, baselineTop)
	if err != nil {
		return err
	}
	th := Thresholds(cfg)
	d := report.DailyData{Zone: zone.Name, Window: w, Loc: cfg.Location, Cur: cur, Base: base}
	d.Findings = analyze.Evaluate(cur, base, th, known(cfg))
	d.Findings, d.VerifiedBots = r.verifyBots(ctx, zone, w, d.Findings)
	// A full day is settled data; collapse needs no settle re-read here.

	logErr := func(what string, err error) {
		if err != nil {
			log.Printf("zone %s: daily %s: %v", zone.Name, what, err)
			d.Gaps = append(d.Gaps, what)
		}
	}
	var cacheCur, cacheBase []cfapi.Face
	cacheCur, err = r.API.Top(ctx, z, w.From, w.To, cfapi.DimCacheStatus, 20, cfapi.Filter{})
	logErr("cache status", err)
	cacheBase, err = r.API.Top(ctx, z, bw.From, bw.To, cfapi.DimCacheStatus, 20, cfapi.Filter{})
	logErr("cache status (baseline)", err)
	if len(cacheCur) > 0 {
		c := analyze.SplitCost(cacheCur, cacheBase)
		d.Cost = &c
	}
	d.DynamicPaths, err = r.pathDeltas(ctx, z, w, bw, 5)
	logErr("dynamic paths", err)

	d.Firewall, err = r.API.FirewallByRule(ctx, z, w.From, w.To, 10)
	if err != nil {
		d.FirewallNA = true
		log.Printf("zone %s: firewall events unavailable: %v", zone.Name, err)
	}

	for _, p := range cfg.Daily.Paths {
		rows, err := r.API.Top(ctx, z, w.From, w.To, cfapi.DimCacheStatus, 20, cfapi.Filter{PathLike: like(p.Path)})
		if err != nil {
			logErr("checkpoint "+p.Path, err)
			continue
		}
		c := analyze.SplitCost(rows, nil)
		label := p.Label
		if label == "" {
			label = p.Path
		}
		d.Checkpoints = append(d.Checkpoints, report.Checkpoint{Label: label, Path: p.Path, OriginReach: c.ExpCur, Max: p.Max})
	}
	for _, a := range cfg.Daily.Artifacts {
		n, err := r.API.Count(ctx, z, w.From, w.To, cfapi.Filter{PathLike: like(a.Path), EdgeStatus: a.EdgeStatus})
		if err != nil {
			logErr("artifact "+a.Label, err)
			continue
		}
		d.Artifacts = append(d.Artifacts, report.ArtifactCount{Label: a.Label, Count: n})
	}

	if st, err := state.Load(StatePath(cfg, zone)); err == nil && st.Active {
		d.ActiveSince = st.FirstAlertAt
		d.ActiveFingerprint = st.Fingerprint
	}

	text := report.Daily(cfg.Report.Language, d)
	log.Printf("zone %s: daily report %s (findings=%d)", zone.Name, w, len(d.Findings))
	return r.Sender.Send(ctx, text)
}

// IsAccessError reports whether err is a token-permission problem, which
// deserves a louder log line than a transient network error.
func IsAccessError(err error) bool { return errors.Is(err, cfapi.ErrNoAccess) }
