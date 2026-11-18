package check

import (
	"context"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/state"
	"github.com/playwjj/flarehound/internal/waf"
)

// auditScope is what a zone's coverage check probes: its hosts and its
// sensitive paths. ok=false: the zone has no list of its own and the
// default list belongs to another zone — coverage is "not configured"
// rather than scored against somebody else's paths.
func (r *Runner) auditScope(zone config.Zone) (hosts []string, paths []waf.Path, ok bool) {
	own := zone.WAFAudit
	if own != nil && len(own.Hosts) > 0 {
		hosts = own.Hosts
	} else {
		for _, h := range r.Cfg.WAFAudit.Hosts {
			if config.HostInZone(h, zone.Name) {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			hosts = []string{zone.Name}
		}
	}
	if own != nil && own.SensitivePaths != nil {
		for _, p := range dedupe(own.SensitivePaths) {
			paths = append(paths, waf.Path{Name: p, Pattern: p})
		}
		return hosts, paths, true
	}
	if !r.Cfg.DefaultAuditScope(zone) {
		return hosts, nil, false
	}
	return hosts, r.sensitivePaths(), true
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// sensitivePaths gathers the default sensitive list: path rules, daily
// checkpoints and waf_audit.sensitive_paths, de-duplicated.
func (r *Runner) sensitivePaths() []waf.Path {
	seen := map[string]bool{}
	var out []waf.Path
	add := func(name, pattern string) {
		if pattern == "" || seen[pattern] {
			return
		}
		seen[pattern] = true
		if name == "" {
			name = pattern
		}
		out = append(out, waf.Path{Name: name, Pattern: pattern})
	}
	for _, p := range r.Cfg.PathRules {
		add(p.Name, p.Path)
	}
	for _, p := range r.Cfg.Daily.Paths {
		add(p.Label, p.Path)
	}
	for _, p := range r.Cfg.WAFAudit.SensitivePaths {
		add("", p)
	}
	return out
}

func (r *Runner) auditEnabled() bool { return r.Rules != nil && !r.Cfg.WAFAudit.Disabled }

// readRuleset reads the custom-rules entrypoint and refreshes the rule
// names used to label firewall events.
func (r *Runner) readRuleset(ctx context.Context, zone config.Zone) (cfapi.Ruleset, error) {
	rs, _, err := r.Rules.Entrypoint(ctx, zone.ZoneID)
	if err != nil {
		return rs, err
	}
	names := map[string]string{}
	for _, x := range rs.Rules {
		if x.Description != "" {
			names[x.ID] = x.Description
		}
	}
	r.mu.Lock()
	if r.ruleNames == nil {
		r.ruleNames = map[string]map[string]string{}
	}
	r.ruleNames[zone.ZoneID] = names
	r.mu.Unlock()
	return rs, nil
}

// ruleHits sums firewall events per rule over the last 7 and 30 days,
// one day per query. nil when the dataset is unavailable or a query fails.
// The window is clamped to the zone's firewall-event retention (3 days on
// some plans): reaching past it gets the whole query rejected. days
// reports how much was actually covered.
func (r *Runner) ruleHits(ctx context.Context, zone config.Zone) (map[string]waf.Hits, int) {
	caps := r.Caps(ctx, zone)
	if !caps.FirewallEnabled {
		return nil, 0
	}
	now := r.now().UTC()
	to := now.Truncate(time.Hour)
	earliest := caps.FirewallFrom(to.Add(-30*24*time.Hour), now)
	out := map[string]waf.Hits{}
	for d := 0; d < 30; d++ {
		end := to.Add(-time.Duration(d) * 24 * time.Hour)
		if !end.After(earliest) {
			break
		}
		start := end.Add(-24 * time.Hour)
		if start.Before(earliest) {
			start = earliest
		}
		hits, err := r.API.RuleHits(ctx, zone.ZoneID, start, end)
		if err != nil {
			log.Printf("zone %s: audit rule hits (%s–%s): %v", zone.Name, start.Format(time.RFC3339), end.Format(time.RFC3339), err)
			if d == 0 {
				return nil, 0
			}
			// The newer days are good: keep them and report what they cover
			// rather than throwing the whole statistic away.
			return out, int(math.Round(to.Sub(end).Hours() / 24))
		}
		for id, n := range hits {
			h := out[id]
			h.D30 += n
			if d < 7 {
				h.D7 += n
			}
			out[id] = h
		}
	}
	return out, int(math.Round(to.Sub(earliest).Hours() / 24))
}

// Audit runs the WAF rule audit for one zone. A missing permission is not
// an error: the result says the audit is not available and why.
func (r *Runner) Audit(ctx context.Context, zone config.Zone) (report.AuditData, error) {
	d := report.AuditData{Zone: zone.Name}
	if !r.auditEnabled() {
		d.NA = "disabled"
		return d, nil
	}
	rs, err := r.readRuleset(ctx, zone)
	if cfapi.IsPermission(err) {
		d.NA = "the read token lacks Zone → WAF: Read"
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("read rulesets: %w", err)
	}
	d.Plan, _ = r.Rules.ZonePlan(ctx, zone.ZoneID) // optional (Zone: Read)
	in := waf.Input{Rules: rs.Rules, Plan: d.Plan, Now: r.now()}
	var scoped bool
	in.Hosts, in.Sensitive, scoped = r.auditScope(zone)
	d.PathsUnset = !scoped
	in.Hits, in.HitsDays = r.ruleHits(ctx, zone)
	if in.Access, err = r.Rules.AccessRules(ctx, zone.ZoneID, ""); err != nil {
		in.AccessNA = true
	}
	d.Result = waf.Audit(in)
	return d, nil
}

// rulesetChanged re-audits when the custom-rules ruleset version changes
// (SPEC 10: "规则集发生变更后自动复检一次") and reports problems. The
// first version seen is only recorded: the daily report covers it.
func (r *Runner) rulesetChanged(ctx context.Context, zone config.Zone, st *state.State) {
	if !r.auditEnabled() {
		return
	}
	rs, err := r.readRuleset(ctx, zone)
	if err != nil {
		if !cfapi.IsPermission(err) {
			log.Printf("zone %s: ruleset version check: %v", zone.Name, err)
		}
		return
	}
	prev := st.RulesetVersion
	st.RulesetVersion = rs.Version
	if prev == "" || prev == rs.Version {
		return
	}
	d, err := r.Audit(ctx, zone)
	if err != nil {
		log.Printf("zone %s: re-audit after ruleset change: %v", zone.Name, err)
		return
	}
	probs := d.Result.Problems()
	log.Printf("zone %s: custom rules changed (version %s → %s), re-audit: %d problem(s)", zone.Name, prev, rs.Version, probs)
	if probs == 0 || d.NA != "" {
		return
	}
	reason := fmt.Sprintf("ruleset changed: version %s → %s", prev, rs.Version)
	if r.Cfg.Report.Language == "zh" {
		reason = fmt.Sprintf("规则集已变更：版本 %s → %s", prev, rs.Version)
	}
	text := report.Audit(r.Cfg.Report.Language, d, reason)
	if err := r.Sender.Send(ctx, r.withConsoleLink(notify.Message{Kind: "audit", Zone: zone.Name, Text: text}, "/audit")); err != nil {
		log.Printf("zone %s: audit notify: %v", zone.Name, err)
	}
}
