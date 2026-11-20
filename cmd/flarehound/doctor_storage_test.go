package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

func TestDoctorStorage(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StateFile: filepath.Join(dir, "state.json"), Location: time.UTC}
	cfg.Archive.File = filepath.Join(dir, "archive.db")
	cfg.Archive.HourlyRetentionDays = 400
	cfg.Console.DBFile = filepath.Join(dir, "console.db")
	cfg.Notify.JSONLFile = filepath.Join(dir, "alerts.jsonl")

	// Nothing on disk yet: nothing is created, nothing is a problem.
	var out bytes.Buffer
	d := &doctorOut{w: &out}
	doctorStorage(d, cfg)
	if d.problems != 0 || !strings.Contains(out.String(), "not created yet") || !strings.Contains(out.String(), "charts/: none") {
		t.Fatalf("empty:\n%s", out.String())
	}
	if _, err := os.Stat(cfg.Archive.File); err == nil {
		t.Fatal("doctor created the archive")
	}

	st, err := store.Open(cfg.Archive.File)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 23, 5, 0, 0, 0, time.UTC)
	if err := st.PutSnapshot("z", store.Hour, from, from.Add(time.Hour), store.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	os.WriteFile(cfg.Notify.JSONLFile, bytes.Repeat([]byte("x"), 297_400), 0o644) // 290.4 KB
	os.WriteFile(cfg.Notify.JSONLFile+".1", make([]byte, 2048), 0o644)
	os.MkdirAll(filepath.Join(dir, "charts"), 0o755)
	for i, name := range []string{"a.png", "b.png", "c.PNG", "notes.txt"} {
		p := filepath.Join(dir, "charts", name)
		os.WriteFile(p, make([]byte, 1024), 0o644)
		mt := time.Date(2026, 11, 18+i, 0, 0, 0, 0, time.UTC)
		os.Chtimes(p, mt, mt)
	}

	out.Reset()
	doctorStorage(d, cfg)
	got := out.String()
	size, _ := fileSize(cfg.Archive.File)
	for _, want := range []string{
		"archive.db: " + fmtBytes(size),
		"oldest hourly snapshot 2026-10-23 (kept 400 days); large prunes return free space",
		"alerts.jsonl: 290.4 KB (rotates at 32.0 MB, keeps 3) + 1 rotated file(s), 2.0 KB",
		"charts/: 3 PNG(s), 3.0 KB, oldest 2026-11-18 (removed after 90 days)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "console.db") || d.problems != 0 {
		t.Errorf("console.db absent must not be listed; problems %d\n%s", d.problems, got)
	}
}

func TestFmtBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 7_444_889: "7.1 MB", 4_300_000: "4.1 MB", 3 << 30: "3.0 GB"} {
		if got := fmtBytes(n); got != want {
			t.Errorf("fmtBytes(%d) = %s, want %s", n, got, want)
		}
	}
}
