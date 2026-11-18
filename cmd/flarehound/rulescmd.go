package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/ruleexec"
	"github.com/playwjj/flarehound/internal/suggest"
	"github.com/playwjj/flarehound/internal/wafkit"
)

const rulesUsage = `
Rule changes (v0.7 execution module; write token; every change is shown in
full, confirmed, backed up, read back and logged — there is no --yes):

  flarehound rules list [--phase custom|ratelimit|cache]   each rule with a plain-words explanation
  flarehound rules recipes                  ready-made rules for common needs, explained
  flarehound rules recipe NAME [--path P] [--action A] [--ips IPS] [--asns ASNS] [--header NAME --secret-env VAR]
                            [--skip SCOPES] [--requests N --period S --timeout S]
  flarehound rules add --action ACTION --expr EXPR --desc TEXT [--before N|ID] [--disabled] [--skip SCOPES]
  flarehound rules edit N|ID [--expr EXPR] [--action ACTION] [--desc TEXT] [--enabled true|false]
  flarehound rules delete N|ID
  flarehound rules move N|ID (--before N|ID | --last)
  flarehound rules backups                  snapshots taken before each change
  flarehound rules restore BACKUP_ID        put a phase back as it was
  flarehound rules log                      execution audit log
  flarehound ratelimit add --path PATTERN [--requests 20 --period 10 --timeout 10 --action managed_challenge]
  flarehound cache add --path PATTERN [--ttl 1d]

  N is the rule's position in "rules list"; --phase selects custom (default),
  ratelimit or cache. --observe 5m watches the changed rule's firewall events.
  --skip (with --action skip) says what a skip rule skips: rules (the remaining
  custom rules, default), ratelimit, managed, bots, legacy — comma-separated.
`

type rulesFlags struct {
	phase, action, expr, desc, before, enabled, path, ttl, skip string
	ips, asns, header, secretEnv                                string
	requestsSet, periodSet, timeoutSet                          bool
	last, disabled                                              bool
	requests, period, timeout                                   int
	observe                                                     time.Duration
}

// rulesCommand runs one execution-module command against one zone.
func rulesCommand(ctx context.Context, cfg *config.Config, x *ruleexec.Executor, runner *check.Runner, zone config.Zone,
	verb string, pos []string, f rulesFlags, in io.Reader, out io.Writer) error {
	sub := ""
	if verb == "rules" {
		if len(pos) == 0 {
			return errors.New("missing subcommand" + rulesUsage)
		}
		sub, pos = pos[0], pos[1:]
	} else {
		if len(pos) == 0 || pos[0] != "add" {
			return fmt.Errorf("usage: flarehound %s add …%s", verb, rulesUsage)
		}
		sub, pos = verb+"-add", pos[1:]
	}
	phase := cfapi.PhaseCustom
	if f.phase != "" {
		p, ok := ruleexec.Phases[f.phase]
		if !ok {
			return fmt.Errorf("--phase must be custom, ratelimit or cache")
		}
		phase = p
	}
	arg := func() (string, error) {
		if len(pos) != 1 {
			return "", fmt.Errorf("%s needs exactly one rule (position or id)", sub)
		}
		return pos[0], nil
	}

	switch sub {
	case "list":
		st, err := x.Load(ctx, phase)
		if err != nil {
			return err
		}
		return listRules(out, zone, st, cfg.Report.Language)
	case "recipes":
		lang := cfg.Report.Language
		for _, r := range wafkit.Recipes() {
			fmt.Fprintf(out, "%s\n  %s\n  %s\n", r.Name, r.T(r.Title, lang), r.T(r.Summary, lang))
			var ps []string
			for _, p := range r.Params {
				d := p.Default
				if d == "" && len(p.Choices) > 0 {
					d = p.Choices[0]
				}
				if d != "" {
					ps = append(ps, recipeFlag(p.Name)+" ("+d+")")
				} else {
					ps = append(ps, recipeFlag(p.Name))
				}
			}
			if len(ps) > 0 {
				fmt.Fprintf(out, "  inputs: %s\n", strings.Join(ps, ", "))
			}
			fmt.Fprintln(out)
		}
		fmt.Fprintln(out, "Run one: flarehound rules recipe NAME [inputs]  — the full change is shown before anything is applied.")
		return nil
	case "backups":
		bs, err := x.Store.RuleBackups(zone.ZoneID, "", 50)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTAKEN\tPHASE\tVERSION\tREASON\tFILE")
		for _, b := range bs {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", b.ID, b.At.In(cfg.Location).Format("2006-01-02 15:04"), ruleexec.PhaseName(b.Phase), b.Version, b.Reason, b.File)
		}
		return tw.Flush()
	case "log":
		cs, err := x.Store.RuleChanges(zone.ZoneID, 50)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "WHEN\tPHASE\tOP\tRULE\tBACKUP\tVERIFIED\tDETAIL")
		for _, c := range cs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t#%d\t%v\t%s\n", c.At.In(cfg.Location).Format("2006-01-02 15:04"), ruleexec.PhaseName(c.Phase), c.Op, c.Rule, c.BackupID, c.Verified, c.Detail)
		}
		return tw.Flush()
	}

	// Everything below changes Cloudflare.
	var st ruleexec.State
	var plan ruleexec.Plan
	var err error
	switch sub {
	case "add", "ratelimit-add", "cache-add":
		if len(pos) != 0 {
			return fmt.Errorf("unexpected arguments %v", pos)
		}
		expr := f.expr
		if expr == "" && f.path != "" {
			expr = suggest.PathExpression(f.path)
		}
		var rule map[string]any
		switch sub {
		case "add":
			if f.action == "" || expr == "" || f.desc == "" {
				return errors.New("rules add needs --action, --expr and --desc")
			}
			rule = ruleexec.CustomRule(expr, f.desc, f.action, !f.disabled)
			if f.action == "skip" {
				ap, err := wafkit.SkipParams(splitScopes(f.skip))
				if err != nil {
					return err
				}
				rule["action_parameters"] = ap
			} else if f.skip != "" {
				return errors.New("--skip only goes with --action skip")
			}
		case "ratelimit-add":
			phase = cfapi.PhaseRateLimit
			if expr == "" {
				return errors.New("ratelimit add needs --path or --expr")
			}
			desc := f.desc
			if desc == "" {
				desc = "FlareHound: rate-limit " + firstNonEmpty(f.path, "expression")
			}
			action := firstNonEmpty(f.action, "managed_challenge")
			rule = ruleexec.RateLimitRule(expr, desc, action, f.requests, f.period, f.timeout)
		case "cache-add":
			phase = cfapi.PhaseCache
			if expr == "" {
				return errors.New("cache add needs --path or --expr")
			}
			ttl, err := parseTTL(firstNonEmpty(f.ttl, "1d"))
			if err != nil {
				return err
			}
			desc := firstNonEmpty(f.desc, "FlareHound: cache "+firstNonEmpty(f.path, "expression"))
			rule = ruleexec.CacheRule(expr, desc, int(ttl.Seconds()))
		}
		if st, err = x.Load(ctx, phase); err != nil {
			return err
		}
		if phase == cfapi.PhaseRateLimit {
			if err := ruleexec.CheckRateLimit(st.Plan, f.period, f.timeout); err != nil {
				return err
			}
		}
		plan, err = st.PlanAdd(rule, f.before)
	case "recipe":
		name, err := arg()
		if err != nil {
			return fmt.Errorf("rules recipe needs a recipe name: %s", strings.Join(wafkit.Names(), ", "))
		}
		r, ok := wafkit.RecipeByName(name)
		if !ok {
			return fmt.Errorf("no recipe %q; see `flarehound rules recipes`", name)
		}
		in := map[string]string{"paths": f.path, "action": f.action, "ips": f.ips, "asns": f.asns, "header": f.header, "skip": f.skip}
		if f.requestsSet {
			in["requests"] = fmt.Sprint(f.requests)
		}
		if f.periodSet {
			in["period"] = fmt.Sprint(f.period)
		}
		if f.timeoutSet {
			in["timeout"] = fmt.Sprint(f.timeout)
		}
		if f.secretEnv != "" {
			if in["secret"] = os.Getenv(f.secretEnv); in["secret"] == "" {
				return fmt.Errorf("--secret-env names %s, but that environment variable is empty", f.secretEnv)
			}
		}
		phase = r.Phase
		if st, err = x.Load(ctx, phase); err != nil {
			return err
		}
		b, err := r.Build(in, st.Plan)
		if err != nil {
			return fmt.Errorf("recipe %s: %w", name, err)
		}
		lang := cfg.Report.Language
		fmt.Fprintf(out, "\n%s\n%s\n\n%s\n\n%s\n", r.T(r.Title, lang), r.T(r.Summary, lang), wrap(r.T(r.Why, lang), 78), wafkit.RuleSentence(b.Rule, lang))
		for _, w := range b.Warnings {
			fmt.Fprintf(out, "NOTE: %s\n", r.T(w, lang))
		}
		plan, err = st.PlanAdd(b.Rule, wafkit.Before(st.Ruleset.Rules, b.Place))
		if err != nil {
			return err
		}
	case "edit":
		sel, err := arg()
		if err != nil {
			return err
		}
		patch := map[string]any{}
		if f.expr != "" {
			patch["expression"] = f.expr
		}
		if f.action != "" {
			patch["action"] = f.action
		}
		if f.skip != "" || f.action == "skip" {
			if f.action != "" && f.action != "skip" {
				return errors.New("--skip only goes with --action skip")
			}
			ap, err := wafkit.SkipParams(splitScopes(f.skip))
			if err != nil {
				return err
			}
			patch["action_parameters"] = ap
		}
		if f.desc != "" {
			patch["description"] = f.desc
		}
		switch f.enabled {
		case "true":
			patch["enabled"] = true
		case "false":
			patch["enabled"] = false
		case "":
		default:
			return errors.New("--enabled takes true or false")
		}
		if len(patch) == 0 {
			return errors.New("rules edit needs at least one of --expr, --action, --skip, --desc, --enabled")
		}
		if st, err = x.Load(ctx, phase); err != nil {
			return err
		}
		plan, err = st.PlanEdit(sel, patch)
		if err != nil {
			return err
		}
	case "delete":
		sel, err := arg()
		if err != nil {
			return err
		}
		if st, err = x.Load(ctx, phase); err != nil {
			return err
		}
		plan, err = st.PlanDelete(sel)
		if err != nil {
			return err
		}
	case "move":
		sel, err := arg()
		if err != nil {
			return err
		}
		if (f.before == "") == !f.last {
			return errors.New("rules move needs exactly one of --before N|ID or --last")
		}
		if st, err = x.Load(ctx, phase); err != nil {
			return err
		}
		plan, err = st.PlanMove(sel, f.before)
		if err != nil {
			return err
		}
	case "restore":
		sel, err := arg()
		if err != nil {
			return err
		}
		var id int64
		if _, err := fmt.Sscan(strings.TrimPrefix(sel, "#"), &id); err != nil {
			return fmt.Errorf("restore takes a backup id (see `flarehound rules backups`)")
		}
		st, plan, err = x.PlanRestore(ctx, id)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown subcommand %q%s", sub, rulesUsage)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\nZone: %s\n", zone.Name)
	for _, l := range plan.Lines {
		fmt.Fprintln(out, l)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(out, "WARNING: %s\n", w)
	}
	fmt.Fprintf(out, "A backup of the %s phase is taken first.\nApply this change? [y/N] ", ruleexec.PhaseName(plan.Phase))
	line, _ := bufio.NewReader(in).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return errAborted
	}
	res, err := x.Apply(ctx, st, plan)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Done — %s (verified by read-back). Backup #%d: %s\nUndo: flarehound rules restore %d\n", res.Detail, res.BackupID, res.BackupFile, res.BackupID)

	if f.observe > 0 && res.RuleID != "" && plan.Phase != cfapi.PhaseCache {
		observe(ctx, runner, zone, res.RuleID, f.observe, out)
	}
	return nil
}

var errAborted = errors.New("aborted, nothing changed")

func splitScopes(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// recipeFlag names the CLI flag for a recipe input.
func recipeFlag(param string) string {
	switch param {
	case "paths":
		return "--path"
	case "secret":
		return "--secret-env VAR"
	}
	return "--" + param
}

// wrap breaks text at spaces (Chinese text has none and stays one line).
func wrap(s string, width int) string {
	var b strings.Builder
	n := 0
	for _, w := range strings.Fields(s) {
		if n > 0 && n+1+len([]rune(w)) > width {
			b.WriteString("\n")
			n = 0
		} else if n > 0 {
			b.WriteString(" ")
			n++
		}
		b.WriteString(w)
		n += len([]rune(w))
	}
	return b.String()
}

func listRules(out io.Writer, zone config.Zone, st ruleexec.State, lang string) error {
	fmt.Fprintf(out, "Zone %s — %s rules: %d of %d (%s plan)", zone.Name, ruleexec.PhaseName(st.Phase), len(st.Ruleset.Rules), st.Limit(), st.Plan)
	if st.Ruleset.Version != "" {
		fmt.Fprintf(out, ", ruleset version %s", st.Ruleset.Version)
	}
	fmt.Fprintln(out)
	for i, r := range st.Ruleset.Rules {
		desc, _ := r["description"].(string)
		expr, _ := r["expression"].(string)
		state := ""
		if r["enabled"] == false {
			state = "  [disabled]"
		}
		if ruleexec.Managed(r) {
			desc += " [FlareHound block]"
		}
		fmt.Fprintf(out, "\n#%d  %v%s  %s\n", i+1, r["action"], state, desc)
		fmt.Fprintf(out, "    → %s\n", wafkit.RuleSentence(r, lang))
		fmt.Fprintf(out, "    %s\n", expr)
	}
	return nil
}

// observe watches a changed rule's firewall events for a while (SPEC
// 13.2: "观察一个短窗口的防火墙事件确认动作生效"). Zero events can simply
// mean no matching traffic, so it reports and never fails.
func observe(ctx context.Context, runner *check.Runner, zone config.Zone, ruleID string, d time.Duration, out io.Writer) {
	if !runner.Caps(ctx, zone).FirewallEnabled {
		fmt.Fprintln(out, "Observation skipped: no firewall events dataset on this plan.")
		return
	}
	start := time.Now()
	fmt.Fprintf(out, "Observing firewall events for %s (analytics lag a few minutes) …\n", d)
	select {
	case <-ctx.Done():
		return
	case <-time.After(d):
	}
	hits, err := runner.API.RuleHits(ctx, zone.ZoneID, start.Add(-time.Minute), time.Now())
	if err != nil {
		fmt.Fprintf(out, "Observation failed: %v\n", err)
		return
	}
	fmt.Fprintf(out, "Rule fired %d time(s) in the observation window", hits[ruleID])
	if hits[ruleID] == 0 {
		fmt.Fprint(out, " — no matching traffic yet, or events not ingested; check `flarehound audit` later")
	}
	fmt.Fprintln(out, ".")
}
