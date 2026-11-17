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
	"github.com/playwjj/flarehound/internal/logx"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/schedule"
)

// version is stamped at release time via -ldflags "-X main.version=..."
// (see .github/workflows/release.yml); local builds report "dev".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	once := flag.Bool("once", false, "run one intraday check and exit")
	daily := flag.Bool("daily", false, "build the daily report now and exit")
	dryRun := flag.Bool("dry-run", false, "print messages to stdout instead of sending them")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("flarehound", version)
		return
	}
	redactor := logx.Install(os.Stderr)
	log.Printf("flarehound %s starting", version)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	redactor.Add(cfg.Secrets()...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	disp := buildDispatcher(cfg, *dryRun)
	runner := &check.Runner{API: cfapi.New(cfg.APIToken), Cfg: cfg, Sender: disp}

	forEachZone := func(kind string, fn func(context.Context, config.Zone) error) {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		if err := disp.Flush(rctx); err != nil {
			log.Printf("outbox: %v", err)
		}
		for _, zone := range cfg.Cloudflare.Zones {
			if err := fn(rctx, zone); err != nil {
				if check.IsAccessError(err) {
					log.Printf("zone %s: %s: %v — the token cannot see this zone/account", zone.Name, kind, err)
				} else {
					log.Printf("zone %s: %s: %v", zone.Name, kind, err)
				}
			}
		}
	}

	if *once || *daily {
		if *once {
			forEachZone("intraday", runner.Intraday)
		}
		if *daily {
			if cfg.Schedule.DailyReportAt == "" {
				log.Fatal("daily report is disabled (schedule.daily_report_at is empty)")
			}
			forEachZone("daily", runner.Daily)
		}
		return
	}

	// Catch up on the newest settled window right away; the state file's
	// last-window marker keeps a restart from double-counting it.
	forEachZone("intraday", runner.Intraday)

	interval, offset := cfg.IntradayInterval(), cfg.IntradayOffset()
	for {
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
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return
		case <-time.After(time.Until(next)):
		}
		// When both fall on the same minute, run both: intraday first.
		if kind == "daily" && schedule.NextIntraday(now, interval, offset).Equal(next) {
			forEachZone("intraday", runner.Intraday)
		}
		if kind == "daily" {
			forEachZone("daily", runner.Daily)
		} else {
			forEachZone("intraday", runner.Intraday)
		}
	}
}

func buildDispatcher(cfg *config.Config, dryRun bool) *notify.Dispatcher {
	outbox := filepath.Join(cfg.DataDir(), "outbox.json")
	if dryRun {
		return notify.NewDispatcher("", notify.Stdout{})
	}
	var chans []notify.Notifier
	if cfg.WebhookURL != "" {
		chans = append(chans, notify.Webhook{URL: cfg.WebhookURL})
	}
	if cfg.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "" {
		chans = append(chans, notify.Telegram{BotToken: cfg.TelegramBotToken, ChatID: cfg.Notify.TelegramChatID})
	}
	if len(chans) == 0 {
		log.Printf("warning: no notification channel configured — findings will only appear in this log")
	}
	return notify.NewDispatcher(outbox, chans...)
}
