package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "archive.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var h0 = time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)

func TestSnapshotUpsertAndSameHour(t *testing.T) {
	s := open(t)
	for k := 0; k <= 30; k++ {
		from := h0.Add(-time.Duration(k) * 24 * time.Hour)
		snap := Snapshot{Metrics: analyze.Metrics{Total: int64(1000 + k), Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 5}}}}
		if err := s.PutSnapshot("z", Hour, from, from.Add(time.Hour), snap); err != nil {
			t.Fatal(err)
		}
	}
	// A different hour must not leak into same-hour samples.
	if err := s.PutSnapshot("z", Hour, h0.Add(-23*time.Hour), h0.Add(-22*time.Hour), Snapshot{Metrics: analyze.Metrics{Total: 9}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.SameHour("z", h0, h0.Add(time.Hour), 28)
	if err != nil || len(got) != 28 {
		t.Fatalf("got %d samples, err %v", len(got), err)
	}
	if got[0].Total != 1001 || got[27].Total != 1028 || got[0].Workers[0].Calls != 5 {
		t.Fatalf("samples = %+v ... %+v", got[0], got[27])
	}

	// Upsert replaces.
	_ = s.PutSnapshot("z", Hour, h0, h0.Add(time.Hour), Snapshot{Metrics: analyze.Metrics{Total: 7}, Cache: []cfapi.Face{{Name: "hit", Count: 3}}})
	snap, ok, err := s.Snapshot("z", Hour, h0)
	if err != nil || !ok || snap.Total != 7 || snap.Cache[0].Count != 3 {
		t.Fatalf("snapshot = %+v %v %v", snap, ok, err)
	}
	if _, ok, _ := s.Snapshot("other-zone", Hour, h0); ok {
		t.Fatal("zones must not mix")
	}
}

func TestFaces(t *testing.T) {
	s := open(t)
	f := []cfapi.Face{{Name: "AS207990", Count: 100}}
	_ = s.TouchFaces("z", DimASN, f, h0)
	f[0].Count = 50
	_ = s.TouchFaces("z", DimASN, f, h0.Add(-48*time.Hour)) // backfilled, older
	f[0].Count = 900
	_ = s.TouchFaces("z", DimASN, f, h0.Add(time.Hour))
	rec, ok, err := s.Face("z", DimASN, "AS207990")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if !rec.FirstSeen.Equal(h0.Add(-48*time.Hour)) || !rec.LastSeen.Equal(h0.Add(time.Hour)) || rec.MaxCount != 900 {
		t.Fatalf("rec = %+v", rec)
	}
	if _, ok, _ := s.Face("z", DimUA, "AS207990"); ok {
		t.Fatal("dims must not mix")
	}
}

func TestAlertsPruneStats(t *testing.T) {
	s := open(t)
	_ = s.RecordAlert("z", h0, "alert", "total_up", []analyze.Finding{{Rule: "total_up"}})
	_ = s.RecordAlert("z", h0.Add(3*time.Hour), "recovered", "", nil)
	as, err := s.Alerts("z", h0, h0.Add(24*time.Hour))
	if err != nil || len(as) != 2 || as[0].Decision != "alert" || as[1].Decision != "recovered" {
		t.Fatalf("alerts = %+v %v", as, err)
	}

	old := h0.Add(-500 * 24 * time.Hour)
	_ = s.PutSnapshot("z", Hour, old, old.Add(time.Hour), Snapshot{})
	_ = s.PutSnapshot("z", Day, old, old.Add(24*time.Hour), Snapshot{})
	_ = s.PutSnapshot("z", Hour, h0, h0.Add(time.Hour), Snapshot{})
	n, err := s.Prune(h0.Add(-400 * 24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	st, err := s.Stats("z")
	if err != nil || st.Hours != 1 || st.Days != 1 || st.Alerts != 2 || !st.Oldest.Equal(old) {
		t.Fatalf("stats = %+v %v", st, err)
	}
}
