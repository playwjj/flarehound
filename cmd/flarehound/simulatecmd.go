package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/sim"
	"github.com/playwjj/flarehound/internal/store"
)

type simArgs struct {
	expr, action, date string
	days               int
	json               bool
}

// runSimulate replays a draft expression against the zone's recent
// traffic and prints the report. Read token only; it changes nothing.
func runSimulate(ctx context.Context, cfg *config.Config, z config.Zone, st *store.Store, a simArgs, out io.Writer) int {
	return simulate(ctx, cfg, z, st, cfapi.New(cfg.APIToken), a, out, time.Now())
}

func simulate(ctx context.Context, cfg *config.Config, z config.Zone, st *store.Store, api sim.API, a simArgs, out io.Writer, now time.Time) int {
	if strings.TrimSpace(a.expr) == "" {
		log.Print("simulate: --expr is required (a Cloudflare rules-language expression)")
		return 2
	}
	action := "block"
	if a.action != "" {
		act, err := block.ParseAction(a.action)
		if err != nil {
			log.Print(err)
			return 2
		}
		action = string(act)
	}
	env := &blockcli.Env{Cfg: cfg, Zone: z, Store: st, Now: func() time.Time { return now }}
	in := env.SimInput(a.expr, action, a.days)
	switch {
	case a.date != "":
		loc := cfg.Location
		if loc == nil {
			loc = time.Local
		}
		d, err := time.ParseInLocation("2006-01-02", a.date, loc)
		if err != nil {
			log.Printf("simulate: --date %q: want YYYY-MM-DD", a.date)
			return 2
		}
		in.From, in.To = d, d.AddDate(0, 0, 1)
		if limit := now.Add(-sim.Settle).Truncate(time.Hour); in.To.After(limit) {
			in.To = limit
		}
		if !in.From.Before(in.To) {
			log.Printf("simulate: %s has not settled yet", a.date)
			return 2
		}
		if now.Sub(in.From) > 30*24*time.Hour {
			log.Printf("simulate: %s is older than Cloudflare's ~30 days of analytics", a.date)
			return 2
		}
	case a.days != 1 && a.days != 7:
		log.Print("simulate: --days takes 7 (default) or 1")
		return 2
	}
	r, err := sim.Run(ctx, api, in)
	if errors.Is(err, sim.ErrParse) {
		log.Print(err)
		return 2
	}
	if err != nil {
		log.Printf("zone %s: simulate: %v", z.Name, err)
		return 1
	}
	if a.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		fmt.Fprint(out, r.Text(cfg.Report.Language, cfg.Location))
	}
	return 0 // not evaluable is an answer too: no numbers, and why
}
