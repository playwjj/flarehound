package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jsonLines reads a JSONL file and fails on any line that is not one
// whole JSON object.
func jsonLines(t *testing.T, p string) int {
	t.Helper()
	fh, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		var v map[string]any
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("%s line %d is not whole JSON: %v", filepath.Base(p), n+1, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFileRotatesAtMessageBoundary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alerts.jsonl")
	f := File{Path: p, MaxBytes: 4 << 10}
	pad := strings.Repeat("x", 900)
	sent := 0
	for i := 0; i < 40; i++ { // ~40 KB through a 4 KB limit: many rotations
		if err := f.Send(context.Background(), Message{Kind: "intraday", Zone: "z", Text: fmt.Sprintf("%d %s", i, pad)}); err != nil {
			t.Fatal(err)
		}
		sent++
	}
	total := 0
	for _, name := range []string{"alerts.jsonl", "alerts.jsonl.1", "alerts.jsonl.2", "alerts.jsonl.3"} {
		q := filepath.Join(dir, name)
		fi, err := os.Stat(q)
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		// A file is rotated only once it reached the limit, and then holds
		// at most one message past it.
		if fi.Size() > f.MaxBytes+1<<10 {
			t.Errorf("%s is %d bytes", name, fi.Size())
		}
		total += jsonLines(t, q)
	}
	if _, err := os.Stat(filepath.Join(dir, "alerts.jsonl.4")); err == nil {
		t.Fatal("more than 3 backups kept")
	}
	if total >= sent || total < 12 {
		t.Fatalf("%d lines kept of %d sent", total, sent)
	}
	// The newest message is the last line of the live file.
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "\"39 ") {
		t.Fatal("newest message not in the live file")
	}
}

func TestFileBelowLimitDoesNotRotate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alerts.jsonl")
	for i := 0; i < 5; i++ {
		if err := (File{Path: p}).Send(context.Background(), Message{Kind: "heartbeat", Text: "alive"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := jsonLines(t, p); n != 5 {
		t.Fatalf("%d lines", n)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("rotated below the limit")
	}
}

func TestPruneCharts(t *testing.T) {
	dir := t.TempDir()
	charts := filepath.Join(dir, "charts")
	if err := os.MkdirAll(charts, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	files := map[string]time.Time{
		"old.png":   now.Add(-100 * 24 * time.Hour),
		"edge.png":  now.Add(-89 * 24 * time.Hour),
		"new.png":   now.Add(-time.Hour),
		"old.txt":   now.Add(-200 * 24 * time.Hour), // not a chart
		"OLDER.PNG": now.Add(-365 * 24 * time.Hour),
	}
	for name, mt := range files {
		p := filepath.Join(charts, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	n, err := PruneCharts(filepath.Join(dir, "alerts.jsonl"), ChartKeep, now)
	if err != nil || n != 2 {
		t.Fatalf("removed %d, %v", n, err)
	}
	for name, keep := range map[string]bool{"old.png": false, "OLDER.PNG": false, "edge.png": true, "new.png": true, "old.txt": true} {
		_, err := os.Stat(filepath.Join(charts, name))
		if (err == nil) != keep {
			t.Errorf("%s: kept=%v, want %v", name, err == nil, keep)
		}
	}
	// No charts directory, no JSONL file: nothing to do.
	if n, err := PruneCharts(filepath.Join(t.TempDir(), "alerts.jsonl"), ChartKeep, now); n != 0 || err != nil {
		t.Fatalf("empty dir: %d %v", n, err)
	}
	if n, err := PruneCharts("", ChartKeep, now); n != 0 || err != nil {
		t.Fatalf("no file: %d %v", n, err)
	}
}
