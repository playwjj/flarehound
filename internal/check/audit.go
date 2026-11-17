package check

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/state"
	"github.com/playwjj/flarehound/internal/waf"
)

// sensitivePaths gathers every configured sensitive pattern: path rules,
// daily checkpoints and waf_audit.sensitive_paths, de-duplicated.
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
	if r.ruleNames == nil {
		r.ruleNames = map[string]map[string]string{}
	}
	r.ruleNames[zone.ZoneID] = names
	return rs, nil
}

// ruleHits sums firewall events per rule over the last 7 and 30 days,
// one day per query. nil when the dataset is unavailable or a query fails.
func (r *Runner) ruleHits(ctx context.Context, zone config.Zone) map[string]waf.Hits {
	if !r.Caps(ctx, zone).FirewallEnabled {
		return nil
	}
	to := r.now().UTC().Truncate(time.Hour)
	out := map[string]waf.Hits{}
	for d := 0; d < 30; d++ {
		end := to.Add(-time.Duration(d) * 24 * time.Hour)
		hits, err := r.API.RuleHits(ctx, zone.ZoneID, end.Add(-24*time.Hour), end)
		if err != nil {
			log.Printf("zone %s: audit rule hits: %v", zone.Name, err)
			return nil
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
	return out
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
	in := waf.Input{Rules: rs.Rules, Sensitive: r.sensitivePaths(), Plan: d.Plan, Now: r.now(), Hits: r.ruleHits(ctx, zone)}
	in.Hosts = r.Cfg.WAFAudit.Hosts
	if len(in.Hosts) == 0 {
		in.Hosts = []string{zone.Name}
	}
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
	if err := r.Sender.Send(ctx, notify.Message{Kind: "audit", Zone: zone.Name, Text: text}); err != nil {
		log.Printf("zone %s: audit notify: %v", zone.Name, err)
	}
}
