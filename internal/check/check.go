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
	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/state"
	"github.com/playwjj/flarehound/internal/store"
	"github.com/playwjj/flarehound/internal/suggest"
)

// API is the subset of the Cloudflare client the runner needs.
type API interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
	FirewallByRule(ctx context.Context, zoneID string, from, to time.Time, limit int) ([]cfapi.Face, error)
	ASNNames(ctx context.Context, zoneID string, from, to time.Time, limit int) (map[int]string, error)
	FirewallTop(ctx context.Context, zoneID string, from, to time.Time, ruleID, dim string, limit int) ([]cfapi.Face, error)
	Capabilities(ctx context.Context, zoneID string) (cfapi.Caps, error)
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
	Store  *store.Store // nil: archive disabled

	caps  map[string]cfapi.Caps                            // per zone, probed once per process
	Now   func() time.Time                                 // default time.Now
	Sleep func(ctx context.Context, d time.Duration) error // default: timer
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

// Caps returns the zone's capability profile, probing it on first use.
// A failed probe assumes everything is available (the pre-probe
// behaviour) and is retried next round.
func (r *Runner) Caps(ctx context.Context, zone config.Zone) cfapi.Caps {
	if c, ok := r.caps[zone.ZoneID]; ok {
		return c
	}
	c, err := r.API.Capabilities(ctx, zone.ZoneID)
	if err != nil {
		log.Printf("zone %s: capability probe failed, assuming full analytics: %v", zone.Name, err)
		return cfapi.AllCaps()
	}
	if r.caps == nil {
		r.caps = map[string]cfapi.Caps{}
	}
	r.caps[zone.ZoneID] = c
	var missing []string
	for _, d := range []string{cfapi.DimASN, "clientASNDescription", cfapi.DimVerifiedBot} {
		if !c.HasDim(d) {
			missing = append(missing, d)
		}
	}
	if !c.FirewallEnabled {
		missing = append(missing, "firewall events")
	}
	if len(missing) > 0 {
		log.Printf("zone %s: not available on this plan, degraded: %s", zone.Name, strings.Join(missing, ", "))
	}
	return c
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
	if r.Caps(ctx, zone).HasDim(cfapi.DimASN) {
		if m.TopASN, err = r.API.Top(ctx, z, from, to, cfapi.DimASN, top, cfapi.Filter{}); err != nil {
			return m, fmt.Errorf("top ASN: %w", err)
		}
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
				if name, ok := r.verifyBot(ctx, zone, w, f.Subject); ok {
					verified = append(verified, name)
					continue
				}
			}
		}
		out = append(out, f)
	}
	return out, verified
}

// verifyBot checks a crawler claim. Cloudflare's own verified-bot
// classification is preferred (available on every plan); the crawler's
// ASNs are the fallback where that dimension is missing.
func (r *Runner) verifyBot(ctx context.Context, zone config.Zone, w schedule.Window, ua string) (string, bool) {
	caps := r.Caps(ctx, zone)
	flt := cfapi.Filter{UserAgent: ua}
	switch {
	case caps.HasDim(cfapi.DimVerifiedBot):
		cats, err := r.API.Top(ctx, zone.ZoneID, w.From, w.To, cfapi.DimVerifiedBot, 5, flt)
		if err != nil {
			log.Printf("zone %s: verify bot: %v", zone.Name, err)
			return "", false
		}
		return analyze.VerifiedByCategory(ua, cats)
	case caps.HasDim(cfapi.DimASN):
		asns, err := r.API.Top(ctx, zone.ZoneID, w.From, w.To, cfapi.DimASN, 5, flt)
		if err != nil {
			log.Printf("zone %s: verify bot: %v", zone.Name, err)
			return "", false
		}
		return analyze.VerifiedBot(ua, asns)
	}
	return "", false
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
func (r *Runner) attribute(ctx context.Context, zone config.Zone, w, bw schedule.Window, fs []analyze.Finding, a *analyze.Attribution, ex *store.Snapshot) {
	z := zone.ZoneID
	logErr := func(what string, err error) {
		if err != nil {
			log.Printf("zone %s: attribution %s: %v", zone.Name, what, err)
		}
	}
	var err error
	if ex != nil && len(ex.Cache) > 0 {
		a.CacheCur = ex.Cache
	} else {
		a.CacheCur, err = r.API.Top(ctx, z, w.From, w.To, cfapi.DimCacheStatus, 20, cfapi.Filter{})
		logErr("cache status", err)
	}
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

	caps := r.Caps(ctx, zone)
	if !caps.FirewallEnabled {
		a.FirewallNA = true
	} else if ex != nil && (len(ex.Firewall) > 0 || ex.FirewallNA) {
		a.Firewall, a.FirewallNA = ex.Firewall, ex.FirewallNA
		if len(a.Firewall) > 10 {
			a.Firewall = a.Firewall[:10]
		}
	} else {
		a.Firewall, err = r.API.FirewallByRule(ctx, z, w.From, w.To, 10)
		if err != nil {
			a.FirewallNA = true
			log.Printf("zone %s: firewall events unavailable: %v", zone.Name, err)
		}
	}

	if caps.HasDim("clientASNDescription") {
		a.ASNNames, err = r.API.ASNNames(ctx, z, w.From, w.To, currentTop)
		logErr("ASN names", err)
	}
}

// sensitive collects every configured sensitive path pattern (path rules
// and daily checkpoints), keyed by rule name / label.
func sensitive(cfg *config.Config) map[string]string {
	m := map[string]string{}
	for _, p := range cfg.PathRules {
		m[p.Name] = p.Path
	}
	for _, p := range cfg.Daily.Paths {
		k := p.Label
		if k == "" {
			k = p.Path
		}
		if _, dup := m[k]; !dup {
			m[k] = p.Path
		}
	}
	return m
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
	long, longN := r.longBaseline(zone, w)
	if long != nil {
		findings = analyze.CrossCheck(findings, analyze.Evaluate(cur, *long, th, known(cfg)))
	}
	var attr analyze.Attribution
	findings, attr.VerifiedBots = r.verifyBots(ctx, zone, w, findings)
	attr.FaceHistory = r.faceHistory(zone, findings)
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

	ex := r.archiveRound(ctx, zone, w, bw, cur, base)

	var text string
	if decision.Notify() {
		if decision != state.DecRecovered {
			r.attribute(ctx, zone, w, bw, findings, &attr, ex)
			firstAlert = st.FirstAlertAt
		}
		hyps := analyze.Hypothesize(cur, base, findings, attr)
		block := analyze.Block(cur, base, attr)
		var sugs []suggest.Suggestion
		if decision != state.DecRecovered {
			sugs = suggest.Suggest(suggest.Input{Cur: cur, Base: base, Findings: findings, Attr: attr,
				Hypotheses: hyps, Block: block, ASNNames: attr.ASNNames,
				Sensitive: sensitive(cfg), MinCount: th.MinCount})
		}
		text = report.Intraday(cfg.Report.Language, report.IntradayData{
			Zone: zone.Name, Window: w, Loc: cfg.Location, Decision: decision,
			Cur: cur, Base: base, Findings: findings, Attr: attr,
			Hypotheses: hyps, Block: block, Suggestions: sugs,
			Since: firstAlert, Long: long, LongN: longN,
		})
		if r.Store != nil {
			if err := r.Store.RecordAlert(zone.ZoneID, w.To, decision.String(), st.Fingerprint, findings); err != nil {
				log.Printf("zone %s: archive alert: %v", zone.Name, err)
			}
		}
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

	caps := r.Caps(ctx, zone)
	if caps.FirewallEnabled {
		d.Firewall, err = r.API.FirewallByRule(ctx, z, w.From, w.To, 10)
		if err != nil {
			d.FirewallNA = true
			log.Printf("zone %s: firewall events unavailable: %v", zone.Name, err)
		}
	} else {
		d.FirewallNA = true
	}
	if !caps.HasDim(cfapi.DimASN) {
		d.NoASN = true
	}

	// Suggestions: the same engine as intraday, on the day's evidence.
	// No per-IP data here, so rate-limit advice (which needs it) cannot fire.
	attr := analyze.Attribution{CacheCur: cacheCur, CacheBase: cacheBase, DynamicPaths: d.DynamicPaths}
	if len(d.Findings) > 0 && caps.HasDim("clientASNDescription") {
		attr.ASNNames, err = r.API.ASNNames(ctx, z, w.From, w.To, currentTop)
		logErr("ASN names", err)
	}
	d.Suggestions = suggest.Suggest(suggest.Input{Cur: cur, Base: base, Findings: d.Findings, Attr: attr,
		Hypotheses: analyze.Hypothesize(cur, base, d.Findings, attr), ASNNames: attr.ASNNames,
		Sensitive: sensitive(cfg), MinCount: th.MinCount})

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

	if r.Store != nil {
		snap := store.Snapshot{Metrics: cur, Cache: cacheCur, Firewall: d.Firewall, FirewallNA: d.FirewallNA}
		for _, p := range d.DynamicPaths {
			snap.DynamicPaths = append(snap.DynamicPaths, cfapi.Face{Name: p.Path, Count: p.Cur})
		}
		if err := r.Store.PutSnapshot(z, store.Day, w.From, w.To, snap); err != nil {
			log.Printf("zone %s: archive daily: %v", zone.Name, err)
		}
		if evs, err := r.Store.ActiveBlocks(z); err != nil {
			logErr("blocks", err)
		} else {
			for _, ev := range evs {
				t := block.Target{Type: block.Type(ev.Type), Value: ev.Value}
				bs := report.BlockStatus{Target: t.String(), Action: ev.Action, Since: ev.At, ExpiresAt: ev.ExpiresAt}
				if caps.FirewallEnabled {
					bs.Attempts, err = block.Attempts(ctx, r.API, z, ev.RuleID, t, w.From, w.To)
				}
				bs.AttemptsNA = !caps.FirewallEnabled || err != nil
				d.Blocks = append(d.Blocks, bs)
			}
		}
		if st, err := r.Store.Stats(z); err == nil {
			d.Archive = &report.ArchiveInfo{Hours: st.Hours, Days: st.Days, Oldest: st.Oldest}
			if samples, err := r.Store.SameHour(z, w.To.Add(-time.Hour), w.To, analyze.LongBaselineDays); err == nil {
				d.Archive.LongSamples = len(samples)
			}
		}
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

// ---- archive (SPEC 6 "本地数据归档") ----

// longBaseline returns the median of the last 28 days' same-hour
// snapshots once the archive has enough of them, else nil.
func (r *Runner) longBaseline(zone config.Zone, w schedule.Window) (*analyze.Metrics, int) {
	if r.Store == nil {
		return nil, 0
	}
	samples, err := r.Store.SameHour(zone.ZoneID, w.From, w.To, analyze.LongBaselineDays)
	if err != nil {
		log.Printf("zone %s: long baseline: %v", zone.Name, err)
		return nil, 0
	}
	if len(samples) < analyze.LongBaselineMinSamples {
		return nil, len(samples)
	}
	m := analyze.Median(samples)
	return &m, len(samples)
}

// faceHistory looks up each new face in the archive, before this round
// touches it, so "never seen before" stays true for genuinely new faces.
func (r *Runner) faceHistory(zone config.Zone, fs []analyze.Finding) map[string]analyze.FaceSeen {
	if r.Store == nil {
		return nil
	}
	out := map[string]analyze.FaceSeen{}
	for _, f := range fs {
		dim := ""
		switch f.Rule {
		case analyze.RuleNewFaceUA:
			dim = store.DimUA
		case analyze.RuleNewFaceASN:
			dim = store.DimASN
		default:
			continue
		}
		rec, ok, err := r.Store.Face(zone.ZoneID, dim, f.Subject)
		if err != nil {
			log.Printf("zone %s: face history: %v", zone.Name, err)
			continue
		}
		if ok {
			out[f.Subject] = analyze.FaceSeen{First: rec.FirstSeen, Last: rec.LastSeen, MaxCount: rec.MaxCount}
		}
	}
	return out
}

// archiveRound stores this round's windows and faces and prunes old
// hours. The current window gets the full breakdown set; the baseline
// window is stored only if absent (it was yesterday's current window, and
// a poorer copy must not overwrite a richer one). Archive failures are
// logged, never fatal: the watch matters more than the history.
func (r *Runner) archiveRound(ctx context.Context, zone config.Zone, w, bw schedule.Window, cur, base analyze.Metrics) *store.Snapshot {
	if r.Store == nil {
		return nil
	}
	z := zone.ZoneID
	logErr := func(what string, err error) {
		if err != nil {
			log.Printf("zone %s: archive %s: %v", zone.Name, what, err)
		}
	}
	snap := store.Snapshot{Metrics: cur}
	var err error
	snap.Cache, err = r.API.Top(ctx, z, w.From, w.To, cfapi.DimCacheStatus, 20, cfapi.Filter{})
	logErr("cache status", err)
	snap.DynamicPaths, err = r.API.Top(ctx, z, w.From, w.To, cfapi.DimPath, 10, cfapi.Filter{CacheStatus: "dynamic"})
	logErr("dynamic paths", err)
	if r.Caps(ctx, zone).FirewallEnabled {
		snap.Firewall, err = r.API.FirewallByRule(ctx, z, w.From, w.To, 25)
		snap.FirewallNA = err != nil
	} else {
		snap.FirewallNA = true
	}

	logErr("snapshot", r.Store.PutSnapshot(z, store.Hour, w.From, w.To, snap))
	if _, ok, err := r.Store.Snapshot(z, store.Hour, bw.From); err == nil && !ok {
		logErr("baseline snapshot", r.Store.PutSnapshot(z, store.Hour, bw.From, bw.To, store.Snapshot{Metrics: base}))
	}
	logErr("faces", r.Store.TouchFaces(z, store.DimUA, cur.TopUA, w.From))
	logErr("faces", r.Store.TouchFaces(z, store.DimASN, cur.TopASN, w.From))
	logErr("faces", r.Store.TouchFaces(z, store.DimUA, base.TopUA, bw.From))
	logErr("faces", r.Store.TouchFaces(z, store.DimASN, base.TopASN, bw.From))

	cutoff := r.now().Add(-time.Duration(r.Cfg.Archive.HourlyRetentionDays) * 24 * time.Hour)
	if n, err := r.Store.Prune(cutoff); err != nil {
		logErr("prune", err)
	} else if n > 0 {
		log.Printf("zone %s: archive pruned %d hourly snapshots older than %s", zone.Name, n, cutoff.Format("2006-01-02"))
	}
	return &snap
}

// Backfill archives the last `days` days of hourly windows from
// Cloudflare (which keeps ~31 days), so the long baseline is available
// right after deployment instead of four weeks later. Windows already in
// the archive are skipped. Calls are paced to stay well inside the
// GraphQL rate limit; progress is logged.
func (r *Runner) Backfill(ctx context.Context, zone config.Zone, days int, pace time.Duration) error {
	if r.Store == nil {
		return errors.New("archive is disabled")
	}
	cfg := r.Cfg
	latest := schedule.IntradayWindow(r.now(), cfg.IntradayInterval(), cfg.IntradayOffset())
	n := days * int(24*time.Hour/cfg.IntradayInterval())
	done, skipped := 0, 0
	for i := 0; i < n; i++ {
		w := latest.Shift(-time.Duration(i) * cfg.IntradayInterval())
		if _, ok, err := r.Store.Snapshot(zone.ZoneID, store.Hour, w.From); err != nil {
			return err
		} else if ok {
			skipped++
			continue
		}
		started := time.Now()
		m, err := r.fetch(ctx, zone, w, baselineTop)
		if err != nil {
			return fmt.Errorf("backfill %s (after %d windows): %w", w, done, err)
		}
		if err := r.Store.PutSnapshot(zone.ZoneID, store.Hour, w.From, w.To, store.Snapshot{Metrics: m}); err != nil {
			return err
		}
		if err := r.Store.TouchFaces(zone.ZoneID, store.DimUA, m.TopUA, w.From); err != nil {
			return err
		}
		if err := r.Store.TouchFaces(zone.ZoneID, store.DimASN, m.TopASN, w.From); err != nil {
			return err
		}
		done++
		if done%24 == 0 {
			log.Printf("zone %s: backfill %d/%d windows (back to %s)", zone.Name, done+skipped, n, w.From.Format("2006-01-02 15:04"))
		}
		// Pace counts the queries' own latency: only wait out the rest.
		if rest := pace - time.Since(started); rest > 0 {
			if err := r.sleep(ctx, rest); err != nil {
				return err
			}
		}
	}
	log.Printf("zone %s: backfill finished: %d windows fetched, %d already archived", zone.Name, done, skipped)
	return nil
}
