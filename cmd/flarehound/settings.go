package main

// Console-managed settings on the watch side (v1.9): reload the overlay
// before each round, report what was applied or rejected, and answer
// test-notification requests with the watch's own environment.

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/control"
	"github.com/playwjj/flarehound/internal/notify"
)

// channelName maps a notifier to its config channel name.
func channelName(n notify.Notifier) string {
	if n.Name() == "file" {
		return config.ChanJSONL
	}
	return n.Name()
}

// buildChannels returns the configured notifiers (without the outbox).
func buildChannels(cfg *config.Config) []notify.Notifier {
	var chans []notify.Notifier
	if cfg.WebhookURL != "" {
		chans = append(chans, notify.Webhook{URL: cfg.WebhookURL})
	}
	if cfg.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "" {
		chans = append(chans, notify.Telegram{BotToken: cfg.TelegramBotToken, ChatID: cfg.Notify.TelegramChatID})
	}
	if cfg.Notify.JSONLFile != "" {
		chans = append(chans, notify.File{Path: cfg.Notify.JSONLFile})
	}
	if u := cfg.Chan.Slack; u != "" {
		chans = append(chans, notify.Slack{URL: u})
	}
	if u := cfg.Chan.Discord; u != "" {
		chans = append(chans, notify.Discord{URL: u})
	}
	if u := cfg.Chan.WeCom; u != "" {
		chans = append(chans, notify.WeCom{URL: u})
	}
	if u := cfg.Chan.Feishu; u != "" {
		chans = append(chans, notify.Feishu{URL: u, Secret: cfg.Chan.FeishuSecret})
	}
	if e := cfg.Notify.Email; e != nil {
		chans = append(chans, notify.Email{Host: e.Host, Port: e.Port, TLS: e.TLS, Username: e.Username,
			Password: cfg.Chan.EmailPassword, From: e.From, To: e.To})
	}
	return chans
}

// stamp identifies the current settings: the config file's and the
// overlay's modification times.
func stamp(cfgPath, overlayPath string) string {
	s := ""
	for _, p := range []string{cfgPath, overlayPath} {
		if st, err := os.Stat(p); err == nil {
			s += st.ModTime().UTC().Format(time.RFC3339Nano) + "|"
		} else {
			s += "-|"
		}
	}
	return s
}

func overlayVersion(c *config.Config) int {
	if c == nil || c.Overlay == nil {
		return 0
	}
	return c.Overlay.Version
}

// settingsWatch keeps the watch's view of its settings and reports it.
type settingsWatch struct {
	cfgPath string
	dataDir string

	mu       sync.Mutex
	status   control.Status
	seen     string // stamp last validated
	applied  string // stamp in use
	redactor interface{ Add(...string) }
}

func (w *settingsWatch) write() {
	w.mu.Lock()
	st := w.status
	w.mu.Unlock()
	st.At, st.Version = time.Now().UTC(), version
	if err := control.WriteStatus(w.dataDir, st); err != nil {
		log.Printf("settings status: %v", err)
	}
}

// started records the configuration the watch started with.
func (w *settingsWatch) started(cfg *config.Config, rejected error) {
	w.mu.Lock()
	w.applied = stamp(w.cfgPath, cfg.OverlayPath)
	w.seen = w.applied
	w.status.Applied = overlayVersion(cfg)
	w.status.Channels = cfg.Channels()
	if rejected != nil {
		w.status.Rejected, w.status.RejectedReason = -1, rejected.Error()
	}
	w.mu.Unlock()
	w.write()
}

// changed validates new settings as soon as they appear (so the console
// can say "accepted" or "rejected: why" without waiting for a round).
func (w *settingsWatch) changed(overlayPath string) {
	s := stamp(w.cfgPath, overlayPath)
	w.mu.Lock()
	if s == w.seen {
		w.mu.Unlock()
		return
	}
	w.seen = s
	w.mu.Unlock()
	nc, err := config.Load(w.cfgPath)
	w.mu.Lock()
	if err != nil {
		ov, _ := config.ReadOverlay(overlayPath)
		w.status.Rejected, w.status.RejectedReason = overlayVersion(&config.Config{Overlay: ov}), err.Error()
		w.status.Pending = 0
		log.Printf("settings: version rejected, keeping the current one: %v", err)
	} else if s != w.applied {
		w.status.Pending, w.status.Rejected, w.status.RejectedReason = overlayVersion(nc), 0, ""
	}
	w.mu.Unlock()
	w.write()
}

// reload returns the configuration to use for the next round: the new
// one when the settings changed and load, else nil (keep the current).
func (w *settingsWatch) reload(overlayPath string) *config.Config {
	s := stamp(w.cfgPath, overlayPath)
	w.mu.Lock()
	same := s == w.applied
	w.mu.Unlock()
	if same {
		return nil
	}
	nc, err := config.Load(w.cfgPath)
	w.mu.Lock()
	w.seen = s
	if err != nil {
		w.status.RejectedReason = err.Error()
		if w.status.Rejected == 0 {
			w.status.Rejected = -1
		}
		w.mu.Unlock()
		w.write()
		log.Printf("settings: not applied, keeping the current ones: %v", err)
		return nil
	}
	w.applied = s
	w.status.Applied, w.status.Pending, w.status.Rejected, w.status.RejectedReason = overlayVersion(nc), 0, 0, ""
	w.status.Channels = nc.Channels()
	w.mu.Unlock()
	if w.redactor != nil {
		w.redactor.Add(nc.Secrets()...)
	}
	w.write()
	log.Printf("settings: version %d applied", overlayVersion(nc))
	return nc
}

func (w *settingsWatch) setNext(t time.Time) {
	w.mu.Lock()
	w.status.NextRound = t
	w.mu.Unlock()
	w.write()
}

// testHandler sends a test through the channels the current settings
// define, loaded fresh with the watch's own environment.
func (w *settingsWatch) testHandler(ctx context.Context, req control.TestRequest) control.TestResult {
	var res control.TestResult
	cfg, err := config.Load(w.cfgPath)
	if err != nil {
		res.SettingsError = err.Error()
		// Still say which channels the configuration in use can reach.
		cfg, err = config.LoadWith(w.cfgPath, config.LoadOptions{NotifySecretsOptional: true})
		if err != nil {
			return res
		}
	}
	res.Settings = overlayVersion(cfg)
	active := map[string]notify.Notifier{}
	for _, n := range buildChannels(cfg) {
		active[channelName(n)] = n
	}
	text := fmt.Sprintf("FlareHound test notification — sent by the watch process on %s at %s, requested in the console by %s. If you can read this, this channel works.",
		hostname(), time.Now().UTC().Format("2006-01-02 15:04 UTC"), req.By)
	for _, ci := range cfg.Channels() {
		if req.Channel != "all" && req.Channel != ci.Name {
			continue
		}
		r := control.ChannelResult{Channel: ci.Name}
		n, ok := active[ci.Name]
		switch {
		case ci.Disabled:
			r.Error = "turned off in the console"
		case len(ci.Missing) > 0:
			r.Error = fmt.Sprintf("environment variable(s) empty in the watch process: %v", ci.Missing)
		case !ok:
			if req.Channel == "all" {
				continue // not configured: nothing to test
			}
			r.Error = "not configured"
			if ci.Note != "" {
				r.Error += ": " + ci.Note
			}
		default:
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := n.Send(sctx, notify.Message{Kind: "test", Text: text})
			cancel()
			if err != nil {
				r.Error = err.Error()
			} else {
				r.OK = true
			}
		}
		res.Results = append(res.Results, r)
	}
	return res
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "this host"
	}
	return h
}

// serve polls for console requests and settings changes until ctx ends.
func (w *settingsWatch) serve(ctx context.Context, overlayPath string) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		w.changed(overlayPath)
		if err := control.Poll(ctx, w.dataDir, time.Now(), w.testHandler); err != nil {
			log.Printf("console requests: %v", err)
		}
	}
}
