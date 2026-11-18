package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/control"
)

func setup(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	jsonl := filepath.Join(dir, "data", "alerts.jsonl")
	raw := `{"cloudflare":{"zones":[{"zone_id":"0123456789abcdef0123456789abcdef","name":"example.com"}]},
		"state_file":"` + filepath.Join(dir, "data", "state.json") + `",
		"notify":{"jsonl_file":"` + jsonl + `"}}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CF_API_TOKEN", "x")
	return cfgPath, filepath.Join(dir, "data"), jsonl
}

func TestWatchSettings(t *testing.T) {
	cfgPath, dataDir, jsonl := setup(t)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	sw := &settingsWatch{cfgPath: cfgPath, dataDir: dataDir}
	sw.started(cfg, nil)

	// A test through every configured channel: the JSONL file receives it.
	id, _ := control.RequestTest(dataDir, "all", "alice", time.Now())
	if err := control.Poll(context.Background(), dataDir, time.Now(), sw.testHandler); err != nil {
		t.Fatal(err)
	}
	res, ok, _ := control.Result(dataDir, id)
	if !ok || len(res.Results) != 1 || !res.Results[0].OK || res.Results[0].Channel != "jsonl" {
		t.Fatalf("test result: %+v", res)
	}
	if raw, _ := os.ReadFile(jsonl); !strings.Contains(string(raw), "test notification") || !strings.Contains(string(raw), "alice") {
		t.Fatal("test notification not written")
	}
	if control.Waiting(dataDir, id) {
		t.Fatal("request still queued after it was answered")
	}

	// A channel whose variable the watch lacks: named in the answer.
	o := &config.Overlay{Version: 1, Notify: map[string]string{"slack_webhook_url_env": "SLACK_HOOK_TYPO"}}
	if err := config.WriteOverlay(cfg.OverlayPath, o); err != nil {
		t.Fatal(err)
	}
	id, _ = control.RequestTest(dataDir, "slack", "alice", time.Now())
	_ = control.Poll(context.Background(), dataDir, time.Now(), sw.testHandler)
	res, _, _ = control.Result(dataDir, id)
	if res.SettingsError == "" || len(res.Results) != 1 || res.Results[0].OK || !strings.Contains(res.Results[0].Error, "SLACK_HOOK_TYPO") {
		t.Fatalf("missing variable not reported: %+v", res)
	}
	// The same settings are rejected for the next round, with the reason.
	time.Sleep(10 * time.Millisecond)
	sw.changed(cfg.OverlayPath)
	st, _, _ := control.ReadStatus(dataDir)
	if st.Rejected != 1 || !strings.Contains(st.RejectedReason, "SLACK_HOOK_TYPO") {
		t.Fatalf("status after a bad change: %+v", st)
	}
	if nc := sw.reload(cfg.OverlayPath); nc != nil {
		t.Fatal("rejected settings applied")
	}

	// Fixed: accepted, pending, then applied by the next round.
	t.Setenv("SLACK_HOOK_TYPO", "https://hooks.slack.test/x")
	o.Version = 2
	if err := config.WriteOverlay(cfg.OverlayPath, o); err != nil {
		t.Fatal(err)
	}
	sw.changed(cfg.OverlayPath)
	if st, _, _ := control.ReadStatus(dataDir); st.Pending != 2 || st.Rejected != 0 {
		t.Fatalf("status after a good change: %+v", st)
	}
	nc := sw.reload(cfg.OverlayPath)
	if nc == nil || nc.Chan.Slack == "" {
		t.Fatal("good settings not applied")
	}
	if st, _, _ := control.ReadStatus(dataDir); st.Applied != 2 || st.Pending != 0 {
		t.Fatalf("status after applying: %+v", st)
	}
	if sw.reload(cfg.OverlayPath) != nil {
		t.Fatal("unchanged settings reloaded")
	}

	// Stale requests are dropped unanswered.
	id, _ = control.RequestTest(dataDir, "all", "alice", time.Now().Add(-time.Hour))
	_ = control.Poll(context.Background(), dataDir, time.Now(), sw.testHandler)
	if _, ok, _ := control.Result(dataDir, id); ok {
		t.Fatal("stale request answered")
	}
}
