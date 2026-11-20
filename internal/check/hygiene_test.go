package check

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The daily report sweeps the JSONL channel's old chart copies; a dry
// run leaves them.
func TestDailyPrunesOldCharts(t *testing.T) {
	for _, dry := range []bool{false, true} {
		cfg := testConfig(t)
		dir := t.TempDir()
		cfg.Notify.JSONLFile = filepath.Join(dir, "alerts.jsonl")
		charts := filepath.Join(dir, "charts")
		if err := os.MkdirAll(charts, 0o755); err != nil {
			t.Fatal(err)
		}
		end := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
		now := end.Add(7 * time.Minute)
		for name, age := range map[string]time.Duration{"old.png": 120 * 24 * time.Hour, "new.png": 2 * 24 * time.Hour} {
			p := filepath.Join(charts, name)
			if err := os.WriteFile(p, []byte("png"), 0o644); err != nil {
				t.Fatal(err)
			}
			mt := now.Add(-age)
			if err := os.Chtimes(p, mt, mt); err != nil {
				t.Fatal(err)
			}
		}
		api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
		api.windows[end.Add(-48*time.Hour)] = normal()
		api.windows[end.Add(-24*time.Hour)] = normal()
		r := &Runner{API: api, Cfg: cfg, Sender: &sink{}, DryRun: dry, Now: func() time.Time { return now }}
		if err := r.Daily(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
			t.Fatal(err)
		}
		_, oldErr := os.Stat(filepath.Join(charts, "old.png"))
		_, newErr := os.Stat(filepath.Join(charts, "new.png"))
		if newErr != nil {
			t.Errorf("dry=%v: recent chart removed", dry)
		}
		if dry && oldErr != nil {
			t.Errorf("dry run removed an old chart")
		}
		if !dry && oldErr == nil {
			t.Errorf("old chart kept after the daily report")
		}
	}
}
