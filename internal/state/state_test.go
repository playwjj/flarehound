package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
)

func f(rule, subject string, cur float64) analyze.Finding {
	return analyze.Finding{Rule: rule, Subject: subject, Cur: cur}
}

func TestLifecycle(t *testing.T) {
	st := &State{}
	now := time.Date(2026, 11, 17, 9, 7, 0, 0, time.UTC)
	step := func(fs []analyze.Finding, want Decision) {
		t.Helper()
		if got := Decide(st, fs, 25, 2, now); got != want {
			t.Fatalf("got %s, want %s (state %+v)", got, want, st)
		}
		now = now.Add(time.Hour)
	}

	step(nil, DecNone)
	step([]analyze.Finding{f("worker_calls_up", "web", 76_000)}, DecAlert)
	// Same anomaly, slightly higher: silent.
	step([]analyze.Finding{f("worker_calls_up", "web", 80_000)}, DecNone)
	// One signal dips under the line and comes back: still the same episode.
	step([]analyze.Finding{f("worker_calls_up", "web", 79_000)}, DecNone)
	// +25% over the reported peak (76k): escalate.
	step([]analyze.Finding{f("worker_calls_up", "web", 96_000)}, DecEscalate)
	step([]analyze.Finding{f("worker_calls_up", "web", 100_000)}, DecNone)
	// A new signal joins the episode.
	step([]analyze.Finding{f("worker_calls_up", "web", 100_000), f("origin_5xx", "", 300)}, DecChanged)
	step([]analyze.Finding{f("origin_5xx", "", 300)}, DecNone)
	// One clean round is not recovery.
	step(nil, DecNone)
	// A blip resets the clean counter.
	step([]analyze.Finding{f("origin_5xx", "", 300)}, DecNone)
	step(nil, DecNone)
	step(nil, DecRecovered)
	if st.Active {
		t.Fatal("state not cleared after recovery")
	}
	step(nil, DecNone)
}

func TestRotatingUAIsOneSignal(t *testing.T) {
	st := &State{}
	now := time.Now()
	if Decide(st, []analyze.Finding{f(analyze.RuleNewFaceUA, "bot/1", 9000)}, 25, 2, now) != DecAlert {
		t.Fatal("first")
	}
	if d := Decide(st, []analyze.Finding{f(analyze.RuleNewFaceUA, "bot/2", 9000)}, 25, 2, now); d != DecNone {
		t.Fatalf("UA rotation re-alerted: %s", d)
	}
}

func TestCollapseNeverEscalatesUpward(t *testing.T) {
	st := &State{}
	c := analyze.Finding{Rule: "collapse_total", Cur: 100, Down: true}
	Decide(st, []analyze.Finding{c}, 25, 2, time.Now())
	c.Cur = 1000
	if d := Decide(st, []analyze.Finding{c}, 25, 2, time.Now()); d != DecNone {
		t.Fatalf("collapse partially recovering must not escalate: %s", d)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "state.json")
	st := &State{}
	Decide(st, []analyze.Finding{f("total_up", "", 5)}, 25, 2, time.Now())
	st.LastWindow = time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active || !got.Keys["total_up"] || got.Peak["total_up"] != 5 || !got.LastWindow.Equal(st.LastWindow) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if missing, err := Load(filepath.Join(t.TempDir(), "nope.json")); err != nil || missing.Active {
		t.Fatal("missing file must load as empty state")
	}
}

func TestCanonicalKeysOnLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	raw := `{"active":true,"fingerprint":"new_face_asn:150436,new_face_asn:AS150436,total_up",
		"keys":{"new_face_asn:150436":true,"new_face_asn:AS150436":true,"total_up":true},
		"peak":{"new_face_asn:150436":900,"new_face_asn:AS150436":500}}`
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Keys) != 2 || !st.Keys["new_face_asn:AS150436"] || st.Peak["new_face_asn:AS150436"] != 900 || len(st.Peak) != 1 {
		t.Fatalf("keys: %+v peak: %+v", st.Keys, st.Peak)
	}
	if st.Fingerprint != "new_face_asn:AS150436,total_up" {
		t.Fatalf("fingerprint: %s", st.Fingerprint)
	}
}
