package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBase(t *testing.T, extra string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	raw := `{"cloudflare":{"zones":[{"zone_id":"0123456789abcdef0123456789abcdef","name":"example.com"}]},
		"state_file":"` + filepath.Join(dir, "data", "state.json") + `",
		"known_faces":{"asns":[15169],"user_agents":["UptimeRobot"]},
		"notify":{"telegram_bot_token_env":"TG_TOKEN","telegram_chat_id":"111","slack_webhook_url_env":"SLACK_URL"` + extra + `}}`
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, filepath.Join(dir, "data", OverlayFile)
}

func TestOverlay(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "x")
	t.Setenv("TG_TOKEN", "bot")
	t.Setenv("SLACK_URL", "https://hooks.slack.test/x")
	t.Setenv("TG2", "bot2")
	path, ovPath := writeBase(t, "")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OverlayPath != ovPath || c.Notify.TelegramChatID != "111" || c.Chan.Slack == "" {
		t.Fatalf("base load: %+v", c.Notify)
	}

	th := DefaultThresholds()
	th.TotalUpPct = 80
	o := &Overlay{Version: 1, Notify: map[string]string{"telegram_chat_id": "222", "telegram_bot_token_env": "TG2"},
		Disabled: []string{ChanSlack}, Thresholds: &th, KnownASNs: []int{15169, 24940}, KnownUAs: []string{"uptimerobot", "MyMonitor"}}
	if err := WriteOverlay(ovPath, o); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Notify.TelegramChatID != "222" || c.TelegramBotToken != "bot2" {
		t.Fatalf("notify overlay: %+v %q", c.Notify, c.TelegramBotToken)
	}
	if c.Chan.Slack != "" || c.Notify.SlackWebhookURLEnv != "" {
		t.Fatal("disabled channel still configured")
	}
	if c.Thresholds.TotalUpPct != 80 {
		t.Fatal("threshold overlay not applied")
	}
	if len(c.KnownFaces.ASNs) != 2 || len(c.KnownFaces.UserAgents) != 2 {
		t.Fatalf("known faces union (no duplicates): %+v", c.KnownFaces)
	}
	if base, _ := LoadWith(path, LoadOptions{NoOverlay: true}); base.Thresholds.TotalUpPct != 35 || base.Notify.TelegramChatID != "111" {
		t.Fatal("NoOverlay still applied the overlay")
	}

	// The previous version is kept for rollback.
	o2 := *o
	o2.Version = 2
	o2.Disabled = nil
	if err := WriteOverlay(ovPath, &o2); err != nil {
		t.Fatal(err)
	}
	if vs, _ := OverlayHistory(ovPath); len(vs) != 2 || vs[0] != 1 || vs[1] != 0 {
		t.Fatalf("history (with v0 = no console settings): %v", vs)
	}
	if v0, _ := ReadOverlayVersion(ovPath, 0); !v0.Empty() {
		t.Fatal("v0 is not empty")
	}
	if prev, _ := ReadOverlayVersion(ovPath, 1); len(prev.Disabled) != 1 {
		t.Fatal("history content")
	}

	// Bad overlays are refused with a reason.
	bad := DefaultThresholds()
	bad.TotalUpPct = 0
	if _, err := LoadWith(path, LoadOptions{Overlay: &Overlay{Thresholds: &bad}}); err == nil || !strings.Contains(err.Error(), "total_up_pct") {
		t.Fatalf("bad threshold accepted: %v", err)
	}
	if _, err := LoadWith(path, LoadOptions{Overlay: &Overlay{Notify: map[string]string{"bot_token": "x"}}}); err == nil {
		t.Fatal("unknown notify field accepted")
	}
	// A variable the watch lacks: an error for the watch, fine for the console.
	missing := &Overlay{Notify: map[string]string{"slack_webhook_url_env": "NOPE_NOT_SET"}}
	if _, err := LoadWith(path, LoadOptions{Overlay: missing}); err == nil || !strings.Contains(err.Error(), "NOPE_NOT_SET") {
		t.Fatalf("missing env var not reported: %v", err)
	}
	if _, err := LoadWith(path, LoadOptions{Overlay: missing, NotifySecretsOptional: true}); err != nil {
		t.Fatalf("console-side load failed on a notification variable: %v", err)
	}
	// Structural validation without any environment (assume every variable set).
	all := func(string) string { return "set" }
	if _, err := LoadWith(path, LoadOptions{Overlay: missing, Getenv: all}); err != nil {
		t.Fatalf("structural validation: %v", err)
	}
	if raw, _ := os.ReadFile(ovPath); strings.Contains(string(raw), "bot2") || strings.Contains(string(raw), "hooks.slack") {
		t.Fatal("a secret value ended up in the overlay file")
	}
}
