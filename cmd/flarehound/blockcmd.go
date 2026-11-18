package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/health"
	"github.com/playwjj/flarehound/internal/logx"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/ruleexec"
	"github.com/playwjj/flarehound/internal/store"
)

const blockUsage = `Commands:

  flarehound audit                                 WAF rule audit now (read token; needs Zone → WAF: Read)
  flarehound calibrate [--days 7]                  compare FlareHound's counts with the Cloudflare dashboard (read token)
  flarehound doctor                                self-check: config, what each token can do, capabilities, archive, heartbeat
  flarehound health [--file heartbeat]             exit 0 if the watch loop's heartbeat is fresh (Docker HEALTHCHECK)
  flarehound console [help]                        the web console (see "flarehound console help")

Blocking commands (separate write token, see README):

  flarehound block <ip|asn|country|ua> <value> [--action block|challenge] [--for 24h|7d] [--reason TEXT] [--yes]
  flarehound unblock <ip|asn|country|ua> <value> [--yes]
  flarehound blocks [--days 7]
  flarehound enforce [--once] [--interval 5m]     expire blocks whose --for has passed

Common flags: -config PATH, --zone NAME|ID (required when several zones are configured)
`

// subcommands lists the verbs main dispatches here.
var subcommands = map[string]bool{"audit": true, "calibrate": true, "doctor": true, "health": true, "block": true, "unblock": true, "blocks": true, "enforce": true, "help": true,
	"rules": true, "ratelimit": true, "cache": true}

// splitArgs separates leading positionals from flags so flags may follow
// the positionals ("block asn 207990 --for 24h").
func splitArgs(args []string) (pos, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return args[:i], args[i:]
		}
	}
	return args, nil
}

// parseTTL accepts Go durations plus a "d" (days) suffix.
func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid --for %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid --for %q (use e.g. 30m, 24h, 7d)", s)
	}
	return d, nil
}

func pickZone(cfg *config.Config, want string) (config.Zone, error) {
	zs := cfg.Cloudflare.Zones
	if want == "" {
		if len(zs) == 1 {
			return zs[0], nil
		}
		return config.Zone{}, errors.New("several zones configured: pass --zone NAME|ID")
	}
	for _, z := range zs {
		if z.Name == want || z.ZoneID == want {
			return z, nil
		}
	}
	return config.Zone{}, fmt.Errorf("zone %q is not in the config", want)
}

func runSubcommand(ctx context.Context, cfgPath, verb string, args []string, redactor *logx.Redactor) int {
	if verb == "help" {
		fmt.Print(blockUsage + rulesUsage + "\n" + consoleUsage)
		return 0
	}
	pos, rest := splitArgs(args)
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.StringVar(&cfgPath, "config", cfgPath, "path to config file")
	zoneArg := fs.String("zone", "", "zone name or ID")
	action := fs.String("action", "", "block or challenge (default: block for ip/ua, challenge for asn/country)")
	ttl := fs.String("for", "", "temporary block: expires after this long (e.g. 24h, 7d)")
	reason := fs.String("reason", "", "why (kept in the audit log)")
	yes := fs.Bool("yes", false, "do not ask for y/N confirmation")
	confirm := fs.String("confirm", "", "pre-typed confirmation value for blocks that can hit real users")
	skipOrigin := fs.Bool("skip-origin-check", false, "block an IP even if the DNS origin check cannot run")
	days := fs.Int("days", 7, "attempt window for `blocks`")
	var rf rulesFlags
	fs.StringVar(&rf.phase, "phase", "", "rules: custom (default), ratelimit or cache")
	fs.StringVar(&rf.expr, "expr", "", "rules: rule expression (Cloudflare rules language)")
	fs.StringVar(&rf.desc, "desc", "", "rules: rule description")
	fs.StringVar(&rf.skip, "skip", "", "rules (action skip): what to skip — rules, ratelimit, managed, bots, legacy (comma-separated; default rules)")
	fs.StringVar(&rf.before, "before", "", "rules: place before rule N|ID")
	fs.BoolVar(&rf.last, "last", false, "rules move: move to the end")
	fs.BoolVar(&rf.disabled, "disabled", false, "rules add: create disabled")
	fs.StringVar(&rf.enabled, "enabled", "", "rules edit: true or false")
	fs.StringVar(&rf.path, "path", "", "ratelimit/cache add: path pattern (* wildcard)")
	fs.StringVar(&rf.ttl, "ttl", "", "cache add: edge TTL (e.g. 4h, 1d)")
	fs.IntVar(&rf.requests, "requests", 20, "ratelimit add: requests per period per IP")
	fs.IntVar(&rf.period, "period", 10, "ratelimit add: period in seconds")
	fs.IntVar(&rf.timeout, "timeout", 10, "ratelimit add: mitigation timeout in seconds")
	fs.DurationVar(&rf.observe, "observe", 0, "rules: watch the changed rule's firewall events for this long")
	hbFile := fs.String("file", health.WatchFile, "health: heartbeat file in the data directory (heartbeat or heartbeat-enforce)")
	hbAge := fs.Duration("max-age", 0, "health: maximum heartbeat age (default: two rounds + 20m, or 15m for the enforcer)")
	once := fs.Bool("once", false, "enforce: one pass, then exit")
	interval := fs.Duration("interval", 5*time.Minute, "enforce: time between passes")
	fs.StringVar(&rf.ips, "ips", "", "rules recipe: IPs or ranges (comma-separated)")
	fs.StringVar(&rf.asns, "asns", "", "rules recipe: ASNs (comma-separated)")
	fs.StringVar(&rf.header, "header", "", "rules recipe: secret header name")
	fs.StringVar(&rf.secretEnv, "secret-env", "", "rules recipe: environment variable holding the secret header value")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "requests":
			rf.requestsSet = true
		case "period":
			rf.periodSet = true
		case "timeout":
			rf.timeoutSet = true
		}
	})
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n\n%s", fs.Args(), blockUsage)
		return 2
	}

	// doctor reports empty notification variables instead of failing on them.
	cfg, err := config.LoadWith(cfgPath, config.LoadOptions{NotifySecretsOptional: verb == "doctor"})
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	redactor.Add(cfg.Secrets()...)

	fail := func(err error) int {
		if errors.Is(err, blockcli.ErrAborted) {
			fmt.Println(err)
			return 1
		}
		log.Print(err)
		return 1
	}

	if verb == "health" { // Docker HEALTHCHECK: quiet unless unhealthy
		limit := *hbAge
		if limit == 0 {
			limit = heartbeatLimit(cfg)
			if *hbFile == health.EnforceFile {
				limit = 15 * time.Minute
			}
		}
		if _, err := health.Check(cfg.DataDir(), *hbFile, limit, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if verb == "doctor" { // read-only probes; reads the write token only to test it
		return runDoctor(ctx, cfg, cfgPath, os.Stdout)
	}

	if verb == "calibrate" { // read-only: never touches the write token
		runner := &check.Runner{API: cfapi.New(cfg.APIToken), Cfg: cfg}
		if !cfg.Archive.Disabled {
			st, err := store.Open(cfg.Archive.File)
			if err != nil {
				log.Printf("archive: %v", err)
				return 1
			}
			defer st.Close()
			runner.Store = st
		}
		if *days < 1 || *days > 365 {
			return fail(errors.New("--days takes 1..365"))
		}
		zs := cfg.Cloudflare.Zones
		if *zoneArg != "" {
			z, err := pickZone(cfg, *zoneArg)
			if err != nil {
				return fail(err)
			}
			zs = []config.Zone{z}
		}
		code := 0
		for _, z := range zs {
			s, err := runner.Calibrate(ctx, z, *days)
			if err != nil {
				log.Printf("zone %s: %v", z.Name, err)
				code = 1
				continue
			}
			fmt.Println(report.Calibration(cfg.Report.Language, z.Name, s))
			fmt.Println()
		}
		return code
	}

	if verb == "audit" { // read-only: never touches the write token
		runner := &check.Runner{API: cfapi.New(cfg.APIToken), Cfg: cfg, Rules: cfapi.NewREST(cfg.APIToken)}
		zs := cfg.Cloudflare.Zones
		if *zoneArg != "" {
			z, err := pickZone(cfg, *zoneArg)
			if err != nil {
				log.Print(err)
				return 1
			}
			zs = []config.Zone{z}
		}
		code := 0
		for _, z := range zs {
			d, err := runner.Audit(ctx, z)
			if err != nil {
				log.Printf("zone %s: %v", z.Name, err)
				code = 1
				continue
			}
			fmt.Println(report.Audit(cfg.Report.Language, d, ""))
			fmt.Println()
		}
		return code
	}

	wt, err := cfg.WriteToken()
	if err != nil {
		log.Print(err)
		return 1
	}
	redactor.Add(wt)

	var st *store.Store
	if !cfg.Archive.Disabled {
		if st, err = store.Open(cfg.Archive.File); err != nil {
			log.Printf("archive: %v", err)
			return 1
		}
		defer st.Close()
	}
	env := func(z config.Zone, actor string) *blockcli.Env {
		return &blockcli.Env{Cfg: cfg, Zone: z, Read: cfapi.New(cfg.APIToken), Write: cfapi.NewREST(wt),
			Store: st, In: os.Stdin, Out: os.Stdout, Actor: actor}
	}

	switch verb {
	case "rules", "ratelimit", "cache":
		if *yes {
			return fail(errors.New("rule changes have no --yes: every change is confirmed after you have seen it (SPEC 13.2)"))
		}
		if st == nil {
			return fail(errors.New("the execution module needs the archive (backups and the audit log live there)"))
		}
		z, err := pickZone(cfg, *zoneArg)
		if err != nil {
			return fail(err)
		}
		rf.action = *action
		x := &ruleexec.Executor{API: cfapi.NewREST(wt), Store: st, ZoneID: z.ZoneID, ZoneName: z.Name,
			BackupDir: filepath.Join(cfg.DataDir(), "backups"), Actor: "cli"}
		runner := &check.Runner{API: cfapi.New(cfg.APIToken), Cfg: cfg}
		if err := rulesCommand(ctx, cfg, x, runner, z, verb, pos, rf, os.Stdin, os.Stdout); err != nil {
			if errors.Is(err, errAborted) {
				fmt.Println(err)
				return 1
			}
			return fail(err)
		}
		return 0

	case "block", "unblock":
		if len(pos) != 2 {
			fmt.Fprint(os.Stderr, blockUsage)
			return 2
		}
		t, err := block.Parse(pos[0], pos[1])
		if err != nil {
			return fail(err)
		}
		z, err := pickZone(cfg, *zoneArg)
		if err != nil {
			return fail(err)
		}
		e := env(z, "cli")
		if verb == "unblock" {
			if err := e.Unblock(ctx, t, *yes, "unblock", *reason); err != nil && !errors.Is(err, blockcli.ErrAuditFailed) {
				return fail(err)
			}
			return 0
		}
		o := blockcli.BlockOpts{Reason: *reason, Yes: *yes, Confirm: *confirm, SkipOriginCheck: *skipOrigin}
		if *action != "" {
			if o.Action, err = block.ParseAction(*action); err != nil {
				return fail(err)
			}
		}
		if o.TTL, err = parseTTL(*ttl); err != nil {
			return fail(err)
		}
		if o.TTL > 0 && st == nil {
			return fail(errors.New("--for needs the archive (it stores expiry times)"))
		}
		if err := e.Block(ctx, t, o); err != nil {
			return fail(err)
		}
		return 0

	case "blocks":
		z, err := pickZone(cfg, *zoneArg)
		if err != nil {
			return fail(err)
		}
		if err := env(z, "cli").List(ctx, *days); err != nil {
			return fail(err)
		}
		return 0

	case "enforce":
		pass := func() {
			defer func() {
				b := health.Beat{At: time.Now().UTC(), Version: version, Role: "enforce", Zones: len(cfg.Cloudflare.Zones), Next: time.Now().Add(*interval)}
				if err := health.Write(cfg.DataDir(), health.EnforceFile, b); err != nil {
					log.Printf("heartbeat: %v", err)
				}
			}()
			for _, z := range cfg.Cloudflare.Zones {
				n, err := env(z, "ttl").Expire(ctx)
				if n > 0 {
					log.Printf("zone %s: %d expired block(s) removed", z.Name, n)
				}
				if err != nil {
					log.Printf("zone %s: enforce: %v", z.Name, err)
				}
			}
		}
		pass()
		if *once {
			return 0
		}
		log.Printf("enforcer running, every %s", *interval)
		t := time.NewTicker(*interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return 0
			case <-t.C:
				pass()
			}
		}
	}
	return 2
}
