package console

// Rule simulator page (v1.19): paste a draft WAF expression, see what it
// would have done over the last days of real traffic. Read-only: it uses
// the read token's analytics and produces no block plan — applying a rule
// still goes through the block review or the rules pages.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/sim"
)

// simForm is the simulator's input, as posted.
type simForm struct {
	Expr   string
	Action string // block | challenge
	Days   int    // 7 or 1
	Before int    // insert before custom rule #N (0: where a FlareHound rule goes)
}

// simInput builds a simulation with the zone's cleaning, calibration and
// known sources (the same as the block review's).
func (s *Server) simInput(z config.Zone, f simForm) sim.Input {
	env := &blockcli.Env{Cfg: s.Cfg, Zone: z, Store: s.Store, Now: s.Now, SimCfg: s.eff()}
	// The read token's REST client reads the rules (position) and lists.
	if ra, ok := s.RulesRead.(sim.RulesAPI); ok {
		env.SimRules = ra
	}
	if la, ok := s.RulesRead.(sim.ListAPI); ok {
		env.SimLists = la
	}
	in := env.SimInput(f.Expr, f.Action, f.Days)
	in.Before = f.Before
	return in
}

func (s *Server) simulatePage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	q := r.URL.Query()
	f := simForm{Expr: strings.TrimSpace(q.Get("expr")), Action: q.Get("action"), Days: sim.DefaultDays}
	if f.Action != "challenge" {
		f.Action = "block"
	}
	if q.Get("days") == "1" {
		f.Days = 1
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(q.Get("before")), "#")); err == nil && n > 0 && n < 1000 {
		f.Before = n
	}
	p := page{Title: s.L(r).t("sim_title"), Zone: z, Nav: "simulate", SimForm: &f}
	api, ok := s.Analytics.(sim.API)
	if !ok {
		p.Err = s.L(r).t("sim_off")
		s.render(w, r, http.StatusOK, "simulate", p)
		return
	}
	if f.Expr == "" {
		s.render(w, r, http.StatusOK, "simulate", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	rep, err := s.sims.Run(ctx, api, s.simInput(z, f))
	switch {
	case errors.Is(err, sim.ErrParse):
		p.Err = err.Error()
	case err != nil:
		p.Err = s.L(r).t("sim_failed") + " " + err.Error()
	default:
		p.Sim = rep
	}
	s.render(w, r, http.StatusOK, "simulate", p)
}

// simLink is the simulator pre-filled with an expression.
func simLink(z config.Zone, expr, action string) string {
	v := url.Values{"z": {z.Name}, "expr": {expr}, "action": {action}, "days": {strconv.Itoa(sim.DefaultDays)}}
	return "/simulate?" + v.Encode()
}
