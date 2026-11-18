package console

// WAF rules in the console (v1.7): every custom and rate-limit rule with a
// plain-words explanation; recipes for common needs; enable / disable /
// reorder / delete / restore. Changes go through the execution module
// (ruleexec: show, back up, apply, read back, log) behind the same review
// flow as blocking: a review token bound to what was reviewed and to the
// ruleset version it was planned on, a fresh TOTP code for accounts that
// have it, and the console audit log written before Cloudflare is touched.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/ruleexec"
	"github.com/playwjj/flarehound/internal/wafkit"
)

// planTolerant reads rules with a token that may lack Zone: Read (the
// plan only sets the quota shown; the read-only list must not fail on it).
type planTolerant struct{ ruleexec.API }

func (p planTolerant) ZonePlan(ctx context.Context, zoneID string) (string, error) {
	plan, err := p.API.ZonePlan(ctx, zoneID)
	if err != nil {
		return "", nil
	}
	return plan, nil
}

var rulePhases = map[string]string{"custom": cfapi.PhaseCustom, "ratelimit": cfapi.PhaseRateLimit}

// RuleView is one rule for display.
type RuleView struct {
	Pos      int
	ID       string
	Action   string
	Desc     string
	Expr     string
	Sentence string
	Enabled  bool
	Managed  bool // a FlareHound block rule (managed on the blocks page)
}

type rulesView struct {
	Phase   string // custom | ratelimit
	Plan    string
	Used    int
	Limit   int
	Version string
	Rules   []RuleView
	Err     string
	At      time.Time // when read from Cloudflare
}

func (s *Server) rulesWriteOn() bool { return s.RulesWrite != nil && s.Store != nil }

// CanEditRules: an admin of a console that holds the write token.
func (s *Server) canEditRules(r *http.Request) bool {
	rq := reqOf(r)
	return s.rulesWriteOn() && rq.User != nil && rq.User.Admin()
}

// requireRules gates rule changes: a console holding the write token.
func (s *Server) requireRules(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.rulesWriteOn() {
			s.render(w, r, http.StatusForbidden, "message", page{Title: s.lang.t("nav_rules"), Msg: s.lang.t("write_off")})
			return
		}
		h(w, r)
	}
}

func (s *Server) executor(z config.Zone, rq *Req, write bool) *ruleexec.Executor {
	api := ruleexec.API(nil)
	switch {
	case write:
		api = s.RulesWrite
	case s.RulesWrite != nil:
		api = planTolerant{s.RulesWrite}
	case s.RulesRead != nil:
		api = planTolerant{s.RulesRead}
	}
	actor := "console"
	if rq != nil && rq.User != nil {
		actor = s.actor(rq)
	}
	return &ruleexec.Executor{API: api, Store: s.Store, ZoneID: z.ZoneID, ZoneName: z.Name,
		BackupDir: filepath.Join(s.Cfg.DataDir(), "backups"), Actor: actor, Now: s.Now}
}

func phaseOf(v string) (string, string) {
	if p, ok := rulePhases[v]; ok {
		return v, p
	}
	return "custom", cfapi.PhaseCustom
}

const rulesTTL = 5 * time.Minute

type rulesEntry struct {
	at time.Time
	v  rulesView
}

// cachedRules returns a phase's rules from the cache (refreshed by the
// background job and after every change) or reads them; fresh forces a read.
func (s *Server) cachedRules(ctx context.Context, z config.Zone, short string, fresh bool) rulesView {
	short, _ = phaseOf(short)
	key := z.ZoneID + "|" + short
	s.rulesMu.Lock()
	e, ok := s.rulesCache[key]
	s.rulesMu.Unlock()
	if ok && !fresh && s.Now().Sub(e.at) < rulesTTL {
		return e.v
	}
	v := s.loadRules(ctx, z, short)
	v.At = s.Now()
	if v.Err == "" {
		s.rulesMu.Lock()
		s.rulesCache[key] = rulesEntry{at: v.At, v: v}
		s.rulesMu.Unlock()
	}
	return v
}

// forgetRules drops a zone's cached rules and audit after a change.
func (s *Server) forgetRules(z config.Zone) {
	s.rulesMu.Lock()
	for k := range s.rulesCache {
		if strings.HasPrefix(k, z.ZoneID+"|") {
			delete(s.rulesCache, k)
		}
	}
	s.rulesMu.Unlock()
	s.auditMu.Lock()
	delete(s.auditCache, z.ZoneID)
	s.auditMu.Unlock()
}

func (s *Server) loadRules(ctx context.Context, z config.Zone, short string) rulesView {
	short, phase := phaseOf(short)
	v := rulesView{Phase: short}
	if s.RulesRead == nil && s.RulesWrite == nil {
		v.Err = s.lang.t("rules_off")
		return v
	}
	st, err := s.executor(z, nil, false).Load(ctx, phase)
	if err != nil {
		v.Err = err.Error()
		return v
	}
	v.Plan, v.Used, v.Limit, v.Version = st.Plan, len(st.Ruleset.Rules), st.Limit(), st.Ruleset.Version
	for i, r := range st.Ruleset.Rules {
		rv := RuleView{Pos: i + 1, Enabled: r["enabled"] != false, Managed: ruleexec.Managed(r), Sentence: wafkit.RuleSentence(r, string(s.lang))}
		rv.ID, _ = r["id"].(string)
		rv.Action, _ = r["action"].(string)
		rv.Desc, _ = r["description"].(string)
		rv.Expr, _ = r["expression"].(string)
		v.Rules = append(v.Rules, rv)
	}
	return v
}

func (s *Server) rulesPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	v := s.cachedRules(ctx, z, r.URL.Query().Get("phase"), r.URL.Query().Get("fresh") == "1")
	p := page{Title: s.lang.t("nav_rules"), Zone: z, Nav: "rules", Rules: &v, Flash: r.URL.Query().Get("ok"), CanRules: s.canEditRules(r)}
	if p.CanRules {
		p.Backups, _ = s.Store.RuleBackups(z.ZoneID, "", 20)
	}
	s.render(w, r, http.StatusOK, "rules", p)
}

// quotas returns each phase's rule count and limit (from the cache).
func (s *Server) quotas(ctx context.Context, z config.Zone) (map[string]rulesView, string) {
	q := map[string]rulesView{}
	plan := ""
	if s.RulesRead == nil && s.RulesWrite == nil {
		return q, plan
	}
	for _, ph := range []string{"custom", "ratelimit"} {
		v := s.cachedRules(ctx, z, ph, false)
		if v.Err == "" {
			q[cfPhase(ph)] = v
			if v.Plan != "" {
				plan = v.Plan
			}
		}
	}
	return q, plan
}

func cfPhase(short string) string { _, p := phaseOf(short); return p }

func (s *Server) recipesPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	q, plan := s.quotas(ctx, z)
	s.render(w, r, http.StatusOK, "recipes", page{Title: s.lang.t("recipes_title"), Zone: z, Nav: "rules", Recipes: wafkit.Recipes(),
		CanRules: s.canEditRules(r), Quota: q, ZonePlan: plan})
}

func (s *Server) recipeForm(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	rc, ok := wafkit.RecipeByName(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	in := map[string]string{}
	for _, p := range rc.Params {
		if !p.Secret {
			in[p.Name] = r.URL.Query().Get(p.Name)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	q, plan := s.quotas(ctx, z)
	s.render(w, r, http.StatusOK, "recipe", page{Title: rc.T(rc.Title, string(s.lang)), Zone: z, Nav: "rules", Recipe: &rc, Inputs: in,
		Quota: q, ZonePlan: plan})
}

// ruleOp is one requested change, as posted.
type ruleOp struct {
	Zone   config.Zone
	Phase  string // custom | ratelimit
	Op     string // recipe enable disable delete up top restore
	Sel    string // rule id / backup id
	Recipe string
	Inputs map[string]string
}

func (o ruleOp) fields(version string) []string {
	keys := make([]string, 0, len(o.Inputs))
	for k := range o.Inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f := []string{"rule", o.Zone.ZoneID, o.Phase, o.Op, o.Sel, o.Recipe, version}
	for _, k := range keys {
		f = append(f, k+"="+o.Inputs[k])
	}
	return f
}

func (s *Server) parseRuleOp(r *http.Request) (ruleOp, error) {
	o := ruleOp{Zone: s.zone(r), Op: r.PostFormValue("op"), Sel: strings.TrimSpace(r.PostFormValue("sel")), Recipe: r.PostFormValue("recipe"), Inputs: map[string]string{}}
	o.Phase, _ = phaseOf(r.PostFormValue("phase"))
	switch o.Op {
	case "recipe":
		rc, ok := wafkit.RecipeByName(o.Recipe)
		if !ok {
			return o, errors.New("unknown recipe")
		}
		for _, p := range rc.Params {
			if v := strings.TrimSpace(r.PostFormValue("in_" + p.Name)); v != "" {
				o.Inputs[p.Name] = truncate(v, 2000)
			}
		}
		o.Phase = map[string]string{cfapi.PhaseCustom: "custom", cfapi.PhaseRateLimit: "ratelimit"}[rc.Phase]
	case "enable", "disable", "delete", "up", "top":
		if o.Sel == "" {
			return o, errors.New("no rule selected")
		}
	case "restore":
		if _, err := strconv.ParseInt(o.Sel, 10, 64); err != nil {
			return o, errors.New("no backup selected")
		}
	default:
		return o, errors.New("unknown operation")
	}
	return o, nil
}

// planRuleOp loads the phase and plans the change.
func (s *Server) planRuleOp(ctx context.Context, x *ruleexec.Executor, o ruleOp) (ruleexec.State, ruleexec.Plan, *wafkit.Built, error) {
	_, phase := phaseOf(o.Phase)
	if o.Op == "restore" {
		id, _ := strconv.ParseInt(o.Sel, 10, 64)
		st, p, err := x.PlanRestore(ctx, id)
		return st, p, nil, err
	}
	st, err := x.Load(ctx, phase)
	if err != nil {
		return st, ruleexec.Plan{}, nil, err
	}
	var p ruleexec.Plan
	switch o.Op {
	case "recipe":
		rc, _ := wafkit.RecipeByName(o.Recipe)
		b, err := rc.Build(o.Inputs, st.Plan)
		if err != nil {
			return st, p, nil, err
		}
		p, err = st.PlanAdd(b.Rule, wafkit.Before(st.Ruleset.Rules, b.Place))
		return st, p, &b, err
	case "enable", "disable":
		p, err = st.PlanEdit(o.Sel, map[string]any{"enabled": o.Op == "enable"})
	case "delete":
		p, err = st.PlanDelete(o.Sel)
	case "up", "top":
		i, _, ferr := st.Find(o.Sel)
		if ferr != nil {
			return st, p, nil, ferr
		}
		if i == 0 {
			return st, p, nil, errors.New(s.lang.t("rule_already_first"))
		}
		target := 0
		if o.Op == "up" {
			target = i - 1
		}
		before, _ := st.Ruleset.Rules[target]["id"].(string)
		p, err = st.PlanMove(o.Sel, before)
	}
	return st, p, nil, err
}

func (s *Server) ruleReview(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	o, err := s.parseRuleOp(r)
	p := page{Title: s.lang.t("rule_review"), Zone: o.Zone, Nav: "rules", RuleOp: &o}
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "rulereview", p)
		return
	}
	s.renderRuleReview(w, r, o, p, rq, "")
}

func (s *Server) renderRuleReview(w http.ResponseWriter, r *http.Request, o ruleOp, p page, rq *Req, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	st, plan, built, err := s.planRuleOp(ctx, s.executor(o.Zone, rq, true), o)
	if o.Op == "recipe" {
		rc, _ := wafkit.RecipeByName(o.Recipe)
		p.Recipe = &rc
		p.Inputs = o.Inputs
	}
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusOK, "rulereview", p)
		return
	}
	p.Plan = &plan
	if built != nil {
		p.Sentence = wafkit.RuleSentence(built.Rule, string(s.lang))
		for _, n := range built.Warnings {
			p.Notes = append(p.Notes, p.Recipe.T(n, string(s.lang)))
		}
	} else if plan.Old != nil {
		p.Sentence = wafkit.RuleSentence(plan.Old, string(s.lang))
	}
	p.Token = s.reviewToken(rq, o.fields(st.Ruleset.Version)...)
	p.RSVersion = st.Ruleset.Version
	p.Err = errMsg
	s.render(w, r, http.StatusOK, "rulereview", p)
}

func (s *Server) ruleApply(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	o, err := s.parseRuleOp(r)
	p := page{Title: s.lang.t("rule_review"), Zone: o.Zone, Nav: "rules", RuleOp: &o}
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "rulereview", p)
		return
	}
	version := r.PostFormValue("version")
	if !s.reviewOK(rq, r.PostFormValue("review"), o.fields(version)...) {
		p.Err = s.lang.t("review_expired")
		s.render(w, r, http.StatusBadRequest, "rulereview", p)
		return
	}
	if msg := s.writeCheck(r); msg != "" {
		s.renderRuleReview(w, r, o, p, rq, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	x := s.executor(o.Zone, rq, true)
	st, plan, _, err := s.planRuleOp(ctx, x, o)
	if err != nil {
		s.renderRuleReview(w, r, o, p, rq, err.Error())
		return
	}
	// The plan was reviewed against one version of the ruleset; if someone
	// changed it since, positions and neighbours may differ: review again.
	if st.Ruleset.Version != version {
		s.renderRuleReview(w, r, o, p, rq, s.lang.t("rules_changed"))
		return
	}
	target := o.Recipe
	if target == "" {
		target = o.Sel
	}
	if err := s.DB.Audit(s.actor(rq), rq.IP, "rule_requested", o.Op+" "+target, o.Zone.Name+" "+o.Phase+": "+strings.Join(plan.Lines, " | ")); err != nil {
		s.fail(w, r, fmt.Errorf("audit log unavailable, nothing changed: %w", err))
		return
	}
	res, err := x.Apply(ctx, st, plan)
	s.forgetRules(o.Zone) // changed (or maybe changed): read it again
	if err != nil {
		s.audit(r, "rule_failed", o.Op+" "+target, err.Error())
		s.renderRuleReview(w, r, o, p, rq, s.lang.t("write_failed")+" "+err.Error())
		return
	}
	s.audit(r, "rule_applied", o.Op+" "+target, fmt.Sprintf("%s; backup #%d", res.Detail, res.BackupID))
	msg := fmt.Sprintf(s.lang.t("rule_done"), res.BackupID)
	http.Redirect(w, r, "/rules?z="+url.QueryEscape(o.Zone.Name)+"&phase="+o.Phase+"&ok="+url.QueryEscape(msg), http.StatusSeeOther)
}
