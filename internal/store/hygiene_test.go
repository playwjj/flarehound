package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// Prune applies one cut point to hourly snapshots, faces and alerts and
// leaves daily rollups and the block / rule audit alone.
func TestPruneScope(t *testing.T) {
	s := open(t)
	cut := h0.Add(-400 * 24 * time.Hour)
	old := cut.Add(-24 * time.Hour)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.PutSnapshot("z", Hour, old, old.Add(time.Hour), Snapshot{}))
	must(s.PutSnapshot("z", Hour, h0, h0.Add(time.Hour), Snapshot{}))
	must(s.PutSnapshot("z", Day, old, old.Add(24*time.Hour), Snapshot{}))
	must(s.TouchFaces("z", DimUA, []cfapi.Face{{Name: "gone-bot", Count: 5}}, old))
	// Seen long ago and again recently: last_seen decides, it stays.
	must(s.TouchFaces("z", DimUA, []cfapi.Face{{Name: "regular", Count: 5}}, old))
	must(s.TouchFaces("z", DimUA, []cfapi.Face{{Name: "regular", Count: 5}}, h0))
	must(s.RecordAlert("z", old, "alert", "f1", nil))
	must(s.RecordAlert("z", h0, "alert", "f2", nil))
	must(s.AddBlockEvent(BlockEvent{At: old, Zone: "z", Op: "block", Type: "ip", Value: "192.0.2.1"}))
	_, err := s.AddRuleBackup(RuleBackup{At: old, Zone: "z", Phase: "p", Data: "[]"})
	must(err)
	must(s.AddRuleChange(RuleChange{At: old, Zone: "z", Phase: "p", Op: "add"}))

	ps, err := s.Prune(cut)
	must(err)
	if ps.Hours != 1 || ps.Faces != 1 || ps.Alerts != 1 || ps.Reclaimed {
		t.Fatalf("pruned %+v", ps)
	}
	if _, ok, _ := s.Face("z", DimUA, "gone-bot"); ok {
		t.Error("face last seen before the cut point survived")
	}
	if f, ok, _ := s.Face("z", DimUA, "regular"); !ok || !f.FirstSeen.Equal(old) {
		t.Errorf("recently seen face: %+v %v", f, ok)
	}
	if as, _ := s.Alerts("z", old.Add(-time.Hour), h0.Add(time.Hour)); len(as) != 1 || as[0].Fingerprint != "f2" {
		t.Errorf("alerts = %+v", as)
	}
	st, _ := s.Stats("z")
	if st.Hours != 1 || st.Days != 1 {
		t.Errorf("stats = %+v", st)
	}
	if ev, _ := s.BlockHistory("z"); len(ev) != 1 {
		t.Errorf("block events = %d", len(ev))
	}
	if bs, _ := s.RuleBackups("z", "", 10); len(bs) != 1 {
		t.Errorf("rule backups = %d", len(bs))
	}
	if cs, _ := s.RuleChanges("z", 10); len(cs) != 1 {
		t.Errorf("rule changes = %d", len(cs))
	}
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// fill archives n old hourly snapshots of about 2 KB each.
func fill(t *testing.T, s *Store, n int, at time.Time) {
	t.Helper()
	pad := strings.Repeat("x", 2000)
	for i := 0; i < n; i++ {
		from := at.Add(-time.Duration(i) * time.Hour)
		snap := Snapshot{Cache: []cfapi.Face{{Name: pad}}}
		if err := s.PutSnapshot("z", Hour, from, from.Add(time.Hour), snap); err != nil {
			t.Fatal(err)
		}
	}
}

// A new archive is created with incremental auto_vacuum, and a large
// prune shrinks the file.
func TestNewArchiveShrinksAfterPrune(t *testing.T) {
	p := filepath.Join(t.TempDir(), "archive.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if m, err := s.AutoVacuum(); err != nil || m != 2 {
		t.Fatalf("auto_vacuum = %d, %v", m, err)
	}
	old := h0.Add(-600 * 24 * time.Hour)
	fill(t, s, 1500, old)
	fill(t, s, 50, h0)
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	before := fileSize(t, p)
	ps, err := s.Prune(h0.Add(-400 * 24 * time.Hour))
	if err != nil || ps.Hours != 1500 || !ps.Reclaimed {
		t.Fatalf("pruned %+v, %v", ps, err)
	}
	after := fileSize(t, p)
	if after >= before/2 {
		t.Fatalf("archive %d → %d bytes: did not shrink", before, after)
	}
	if st, _ := s.Stats("z"); st.Hours != 50 {
		t.Fatalf("hours left = %d", st.Hours)
	}
}

// An archive created before v1.18 (auto_vacuum NONE) opens as before,
// keeps its mode and its size: pages are reused, not returned.
func TestLegacyArchiveKeepsSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "archive.db")
	raw, err := sql.Open("sqlite", "file:"+p+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if m, _ := s.AutoVacuum(); m != 0 {
		t.Fatalf("legacy archive auto_vacuum = %d, want 0", m)
	}
	fill(t, s, 1500, h0.Add(-600*24*time.Hour))
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	before := fileSize(t, p)
	ps, err := s.Prune(h0.Add(-400 * 24 * time.Hour))
	if err != nil || ps.Hours != 1500 || ps.Reclaimed {
		t.Fatalf("pruned %+v, %v", ps, err)
	}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if after := fileSize(t, p); after != before {
		t.Fatalf("legacy archive %d → %d bytes", before, after)
	}
	if got, _ := s.OldestHour(); !got.IsZero() {
		t.Fatalf("oldest hour = %v", got)
	}
}
