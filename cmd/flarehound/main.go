// FlareHound: a self-hosted watchdog for websites behind Cloudflare.
//
// v0.1 skeleton: the intraday check (last full hour vs. yesterday, same
// hour) runs end to end — query, evaluate, dedupe, notify. The daily
// digest lands in v0.2 (see SPEC.md roadmap).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/state"
)

// version is stamped at release time via -ldflags "-X main.version=..."
// (see .github/workflows/release.yml); local builds report "dev".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	once := flag.Bool("once", false, "run one intraday check and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("flarehound", version)
		return
	}
	log.Printf("flarehound %s starting", version)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	client := cfapi.New(cfg.APIToken)
	notifier := buildNotifier(cfg)
	th := thresholds(cfg)

	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, zone := range cfg.Cloudflare.Zones {
			if err := checkZone(ctx, cfg, client, notifier, th, zone); err != nil {
				log.Printf("zone %s: %v", zone.Name, err)
			}
		}
	}

	run()
	if *once {
		return
	}
	tick := time.NewTicker(cfg.IntradayInterval())
	defer tick.Stop()
	for range tick.C {
		run()
	}
}

func thresholds(cfg *config.Config) analyze.Thresholds {
	t := cfg.Thresholds
	return analyze.Thresholds{
		TotalUpPct:         t.TotalUpPct,
		WorkerCallsUpPct:   t.WorkerCallsUpPct,
		CPUP50UpPct:        t.CPUP50UpPct,
		DynamicUpPct:       t.DynamicUpPct,
		Origin5xxMultiple:  t.Origin5xxMultiple,
		Origin5xxMin:       t.Origin5xxMin,
		NewFaceMinCount:    t.NewFaceMinCount,
		CollapseDownPct:    t.CollapseDownPct,
		EscalationPct:      t.EscalationPct,
		RecoveryCleanRound: t.RecoveryCleanRound,
	}
}

func buildNotifier(cfg *config.Config) notify.Notifier {
	var ns notify.Multi
	if cfg.Notify.WebhookURL != "" {
		ns = append(ns, notify.Webhook{URL: cfg.Notify.WebhookURL})
	}
	if cfg.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "" {
		ns = append(ns, notify.Telegram{BotToken: cfg.TelegramBotToken, ChatID: cfg.Notify.TelegramChatID})
	}
	return ns
}

// statePath derives a per-zone state file when several zones are watched,
// so their anomaly state machines never mix.
func statePath(cfg *config.Config, zone config.Zone) string {
	if len(cfg.Cloudflare.Zones) <= 1 {
		return cfg.StateFile
	}
	slug := strings.NewReplacer(".", "-", "/", "-").Replace(zone.Name)
	return strings.TrimSuffix(cfg.StateFile, ".json") + "-" + slug + ".json"
}

func fetchMetrics(ctx context.Context, client *cfapi.Client, cfg *config.Config, zone config.Zone, from, to time.Time, topLimit int) (analyze.Metrics, error) {
	var m analyze.Metrics
	var err error
	if m.Total, err = client.TotalRequests(ctx, zone.ZoneID, from, to); err != nil {
		return m, err
	}
	if m.Dynamic, err = client.DynamicRequests(ctx, zone.ZoneID, from, to); err != nil {
		return m, err
	}
	if m.Origin5xx, err = client.Origin5xx(ctx, zone.ZoneID, from, to); err != nil {
		return m, err
	}
	if m.TopUA, err = client.TopUserAgents(ctx, zone.ZoneID, from, to, topLimit); err != nil {
		return m, err
	}
	if m.TopASN, err = client.TopASNs(ctx, zone.ZoneID, from, to, topLimit); err != nil {
		return m, err
	}
	// TODO(v0.3): aggregate all of the zone's workers; the skeleton
	// evaluates the first listed worker, which covers the common
	// single-frontend-worker layout.
	if len(zone.Workers) > 0 {
		calls, cpu, err := client.WorkerStats(ctx, cfg.Cloudflare.AccountID, zone.Workers[0], from, to)
		if err != nil {
			return m, err
		}
		m.WorkerCalls = calls
		m.CPUP50ms = cpu
	}
	return m, nil
}

func checkZone(ctx context.Context, cfg *config.Config, client *cfapi.Client, notifier notify.Notifier, th analyze.Thresholds, zone config.Zone) error {
	// Windows: last full clock hour vs. the same hour yesterday.
	// Analytics ingestion lags a few minutes; the scheduler's offset
	// from the hour boundary absorbs it.
	now := time.Now().UTC().Truncate(time.Hour)
	curFrom, curTo := now.Add(-time.Hour), now
	baseFrom, baseTo := curFrom.Add(-24*time.Hour), curTo.Add(-24*time.Hour)

	cur, err := fetchMetrics(ctx, client, cfg, zone, curFrom, curTo, 10)
	if err != nil {
		return err
	}
	base, err := fetchMetrics(ctx, client, cfg, zone, baseFrom, baseTo, 25)
	if err != nil {
		return err
	}

	findings := analyze.Evaluate(cur, base, th)

	sp := statePath(cfg, zone)
	st, err := state.Load(sp)
	if err != nil {
		return err
	}
	decision := state.Decide(st, findings, float64(cur.Total), float64(cur.WorkerCalls), th.EscalationPct, th.RecoveryCleanRound)
	if err := st.Save(sp); err != nil {
		return err
	}

	switch decision {
	case state.DecAlert, state.DecEscalate, state.DecRecovered:
		text := report.Render(decision, zone.Name, cur, base, findings)
		if err := notifier.Send(ctx, text); err != nil {
			return err
		}
		log.Printf("zone %s: notified (decision=%d, findings=%d)", zone.Name, decision, len(findings))
	default:
		log.Printf("zone %s: quiet (findings=%d, active=%v)", zone.Name, len(findings), st.Active)
	}
	return nil
}
