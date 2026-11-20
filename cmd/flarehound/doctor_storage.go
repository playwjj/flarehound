package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/store"
)

// doctorStorage shows what FlareHound keeps on disk, file by file, so a
// slow build-up is visible long before it matters. Read-only: files are
// stat'ed, and the archive is opened only when it exists.
func doctorStorage(d *doctorOut, cfg *config.Config) {
	d.head("Storage (" + cfg.DataDir() + ")")

	if cfg.Archive.Disabled {
		d.ok("archive: disabled")
	} else if size, ok := fileSize(cfg.Archive.File); !ok {
		d.ok("archive %s: not created yet", cfg.Archive.File)
	} else {
		line := fmt.Sprintf("%s: %s%s", filepath.Base(cfg.Archive.File), fmtBytes(size), walNote(cfg.Archive.File))
		if st, err := store.Open(cfg.Archive.File); err != nil {
			d.bad("%s; %v", line, err)
		} else {
			if t, err := st.OldestHour(); err == nil && !t.IsZero() {
				line += fmt.Sprintf("; oldest hourly snapshot %s (kept %d days)", t.In(cfg.Location).Format("2006-01-02"), cfg.Archive.HourlyRetentionDays)
			}
			if m, err := st.AutoVacuum(); err == nil {
				line += "; " + vacuumNote(m)
			}
			st.Close()
			d.ok("%s", line)
		}
	}

	if size, ok := fileSize(cfg.Console.DBFile); ok {
		d.ok("%s: %s%s", filepath.Base(cfg.Console.DBFile), fmtBytes(size), walNote(cfg.Console.DBFile))
	}

	if p := cfg.Notify.JSONLFile; p != "" {
		size, _ := fileSize(p)
		line := fmt.Sprintf("%s: %s (rotates at %s, keeps %d)", filepath.Base(p), fmtBytes(size), fmtBytes(notify.JSONLMaxBytes), notify.JSONLBackups)
		var n int
		var total int64
		for i := 1; i <= notify.JSONLBackups+1; i++ { // +1: one left by hand is still counted
			if s, ok := fileSize(fmt.Sprintf("%s.%d", p, i)); ok {
				n++
				total += s
			}
		}
		if n > 0 {
			line += fmt.Sprintf(" + %d rotated file(s), %s", n, fmtBytes(total))
		}
		d.ok("%s", line)
		cn, csize, oldest := chartsDir(filepath.Join(filepath.Dir(p), "charts"))
		if cn > 0 {
			d.ok("charts/: %d PNG(s), %s, oldest %s (removed after %d days)", cn, fmtBytes(csize), oldest.In(cfg.Location).Format("2006-01-02"), int(notify.ChartKeep.Hours()/24))
		} else {
			d.ok("charts/: none")
		}
	}
}

func fileSize(p string) (int64, bool) {
	if p == "" {
		return 0, false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return 0, false
	}
	return fi.Size(), true
}

// walNote is " (+ WAL 4.1 MB)" when the database has a write-ahead log.
// A WAL of a few MB is SQLite's normal checkpoint ceiling, not a leak.
func walNote(db string) string {
	if s, ok := fileSize(db + "-wal"); ok && s > 0 {
		return " (+ WAL " + fmtBytes(s) + ")"
	}
	return ""
}

func vacuumNote(mode int) string {
	if mode == 2 {
		return "large prunes return free space"
	}
	return "created before v1.18: freed space is reused, the file does not shrink"
}

func chartsDir(dir string) (n int, size int64, oldest time.Time) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, time.Time{}
	}
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.EqualFold(filepath.Ext(e.Name()), ".png") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		n++
		size += fi.Size()
		if oldest.IsZero() || fi.ModTime().Before(oldest) {
			oldest = fi.ModTime()
		}
	}
	return n, size, oldest
}

// fmtBytes: 0 B, 812 B, 290.4 KB, 7.1 MB, 1.2 GB (1024-based).
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n)/unit, 0
	for v >= unit && i < 3 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, []string{"KB", "MB", "GB", "TB"}[i])
}
