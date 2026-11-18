// FlareHound: a self-hosted watchdog for websites behind Cloudflare.
//
// One process runs two schedules (SPEC 7.1): the intraday watch, a few
// minutes after every clock hour, and the daily report at a fixed local
// time. Both are read-only against Cloudflare.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/health"
	"github.com/playwjj/flarehound/internal/logx"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/store"
)

// version is stamped at release time via -ldflags "-X main.version=..."
// (see .github/workflows/release.yml); local builds report "dev".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	once := flag.Bool("once", false, "run one intraday check and exit")
	daily := flag.Bool("daily", false, "build the daily report now and exit")
	dryRun := flag.Bool("dry-run", false, "print messages to stdout instead of sending them")
	backfill := flag.Int("backfill", 0, "archive the last N days (1-30) of hourly windows from Cloudflare, then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: flarehound [flags]            run the watchdog\n       flarehound <command> [args]   see `flarehound help`\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("flarehound", version)
		return
	}
	redactor := logx.Install(os.Stderr)

	// Blocking commands: they alone may read the write token.
	if flag.NArg() > 0 {
		verb := flag.Arg(0)
		if verb == "console" { // the web console: its own process and flags
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			code := runConsole(ctx, *cfgPath, flag.Args()[1:], redactor)
			stop()
			os.Exit(code)
		}
		if !subcommands[verb] {
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", verb, blockUsage)
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runSubcommand(ctx, *cfgPath, verb, flag.Args()[1:], redactor)
		stop()
		os.Exit(code)
	}

	log.Printf("flarehound %s starting", version)

	cfg, err := config.Load(*cfgPath)
	var rejected error
	if err != nil {
		// Settings changed in the console that do not load (e.g. a variable
		// this process lacks) must not stop the watch: run on config.json
		// alone and report why.
		base, berr := config.LoadWith(*cfgPath, config.LoadOptions{NoOverlay: true})
		if berr != nil {
			log.Fatalf("config: %v", err)
		}
		log.Printf("settings: console settings rejected, running on %s alone: %v", *cfgPath, err)
		cfg, rejected = base, err
	}
	redactor.Add(cfg.Secrets()...)
	sw := &settingsWatch{cfgPath: *cfgPath, dataDir: cfg.DataDir(), redactor: redactor}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	disp := buildDispatcher(cfg, *dryRun)
	runner := &check.Runner{API: cfapi.New(cfg.APIToken), Cfg: cfg, Sender: disp, Rules: cfapi.NewREST(cfg.APIToken), DryRun: *dryRun}
	if !cfg.Archive.Disabled {
		st, err := store.Open(cfg.Archive.File)
		if err != nil {
			log.Fatalf("archive: %v", err)
		}
		defer st.Close()
		runner.Store = st
	}

	if *backfill != 0 {
		if *backfill < 1 || *backfill > 30 {
			log.Fatal("-backfill takes 1..30 days (Cloudflare keeps ~31 days of analytics)")
		}
		if runner.Store == nil {
			log.Fatal("-backfill needs the archive (archive.disabled is true)")
		}
		for _, zone := range cfg.Cloudflare.Zones {
			// ~1 query per second keeps well inside the GraphQL rate limit.
			queries := 5 + len(zone.Workers) + len(cfg.PathRules)
			pace := time.Duration(queries) * time.Second
			log.Printf("zone %s: backfilling %d days, ~%d queries per window, ~%s total", zone.Name, *backfill, queries,
				(time.Duration(*backfill*24) * pace).Round(time.Minute))
			if err := runner.Backfill(ctx, zone, *backfill, pace); err != nil {
				log.Fatalf("zone %s: %v", zone.Name, err)
			}
		}
		return
	}

	forEachZone := func(kind string, fn func(context.Context, config.Zone) error) []string {
		var failed []string
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		if err := disp.Flush(rctx); err != nil {
			log.Printf("outbox: %v", err)
		}
		zones := cfg.Cloudflare.Zones
		for i, err := range check.Parallel(rctx, zones, cfg.Schedule.MaxParallelZones, fn) {
			if err == nil {
				continue
			}
			failed = append(failed, zones[i].Name+": "+err.Error())
			if check.IsAccessError(err) {
				log.Printf("zone %s: %s: %v — the token cannot see this zone/account", zones[i].Name, kind, err)
			} else {
				log.Printf("zone %s: %s: %v", zones[i].Name, kind, err)
			}
		}
		return failed
	}

	// Dead-man switch: every watch round says it is alive — anomaly or not —
	// in data/heartbeat, the JSONL file and the optional ping URL. Never on
	// chat channels: a heartbeat there would be noise.
	intraday := func() {
		interval, offset := cfg.IntradayInterval(), cfg.IntradayOffset()
		failed := forEachZone("intraday", runner.Intraday)
		if *dryRun {
			return
		}
		b := health.Beat{At: time.Now().UTC(), Version: version, Role: "watch", Zones: len(cfg.Cloudflare.Zones),
			Errors: failed, Next: schedule.NextIntraday(time.Now(), interval, offset)}
		b.WriteTokenInEnv = os.Getenv(cfg.Blocking.WriteTokenEnv) != ""
		if err := health.Write(cfg.DataDir(), health.WatchFile, b); err != nil {
			log.Printf("heartbeat: %v", err)
		}
		if cfg.Notify.JSONLFile != "" {
			text := fmt.Sprintf("FlareHound alive: %d zone(s) checked, %d error(s); next run %s", b.Zones, len(failed), b.Next.Format(time.RFC3339))
			m := notify.Message{Kind: "heartbeat", Text: text, Rules: failed}
			if err := (notify.File{Path: cfg.Notify.JSONLFile}).Send(ctx, m); err != nil {
				log.Printf("heartbeat: %v", err)
			}
		}
		if cfg.HeartbeatURL != "" {
			pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			if err := health.Ping(pctx, cfg.HeartbeatURL, len(failed) > 0); err != nil {
				log.Printf("%v", err)
			}
			cancel()
		}
	}

	if *once || *daily {
		if *once {
			intraday()
		}
		if *daily {
			if cfg.Schedule.DailyReportAt == "" {
				log.Print("daily report is disabled (schedule.daily_report_at is empty)")
				return
			}
			forEachZone("daily", runner.Daily)
		}
		return
	}

	// Settings changed in the console apply before the next round; test
	// notifications are answered right away.
	overlayPath := cfg.OverlayPath
	sw.started(cfg, rejected)
	if !*dryRun {
		go sw.serve(ctx, overlayPath)
	}
	applySettings := func() {
		nc := sw.reload(overlayPath)
		if nc == nil {
			return
		}
		cfg = nc
		disp = buildDispatcher(nc, *dryRun)
		runner.Cfg, runner.Sender = nc, disp
	}

	// Catch up on the newest settled window right away; the state file's
	// last-window marker keeps a restart from double-counting it.
	intraday()

	for {
		interval, offset := cfg.IntradayInterval(), cfg.IntradayOffset()
		now := time.Now()
		next := schedule.NextIntraday(now, interval, offset)
		kind := "intraday"
		if cfg.Schedule.DailyReportAt != "" {
			d, err := schedule.NextDaily(now, cfg.Schedule.DailyReportAt, cfg.Location, offset)
			if err == nil && !d.After(next) {
				next, kind = d, "daily"
			}
		}
		log.Printf("next %s run at %s", kind, next.In(cfg.Location).Format(time.RFC3339))
		sw.setNext(next)
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return
		case <-time.After(time.Until(next)):
		}
		applySettings()
		// When both fall on the same minute, run both: intraday first.
		if kind == "daily" && schedule.NextIntraday(now, interval, offset).Equal(next) {
			intraday()
		}
		if kind == "daily" {
			forEachZone("daily", runner.Daily)
		} else {
			intraday()
		}
	}
}

func buildDispatcher(cfg *config.Config, dryRun bool) *notify.Dispatcher {
	outbox := filepath.Join(cfg.DataDir(), "outbox.json")
	if dryRun {
		return notify.NewDispatcher("", notify.Stdout{})
	}
	chans := buildChannels(cfg)
	if len(chans) == 0 {
		log.Printf("warning: no notification channel configured — findings will only appear in this log")
	}
	return notify.NewDispatcher(outbox, chans...)
}
