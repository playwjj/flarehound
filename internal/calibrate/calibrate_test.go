package calibrate

import (
	"testing"
	"time"
)

func TestSummarize(t *testing.T) {
	d0 := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	days := []Day{
		// the live 404401.xyz day: adaptive 21,796 vs dashboard 16,494
		{Date: d0, DashRequests: 16494, AdRequests: 21796, DashCached: 336, AdCached: 900, SampleInterval: 1.08},
		{Date: d0.AddDate(0, 0, -1), DashRequests: 10000, AdRequests: 13000, DashCached: 50, AdCached: 900, SampleInterval: 1.0},
		{Date: d0.AddDate(0, 0, -2), DashRequests: 10000, AdRequests: 40000, Dash5xx: 100, Ad5xx: 120, SampleInterval: 1.2}, // odd day
	}
	s := Summarize(days, 1000)
	if s.Requests < 1.31 || s.Requests > 1.33 || s.Verdict != AdaptiveHi {
		t.Fatalf("median ratio %v %s", s.Requests, s.Verdict)
	}
	if !s.HasCached || s.Cached < 2.6 || s.Cached > 2.7 { // the 50-request day is ignored
		t.Fatalf("cached %v %v", s.Cached, s.HasCached)
	}
	if !s.Has5xx || s.Edge5xx != 1.2 {
		t.Fatalf("5xx %v", s.Edge5xx)
	}
	if s.MinCountDash < 750 || s.MinCountDash > 770 {
		t.Fatalf("min_count in dashboard units %d", s.MinCountDash)
	}
	if s.SampleRate < 0.92 || s.SampleRate > 0.93 {
		t.Fatalf("sample rate %v", s.SampleRate)
	}
	if Summarize(nil, 1000).Verdict != NoData {
		t.Fatal("no data")
	}
	if v := Summarize([]Day{{DashRequests: 100, AdRequests: 104}}, 1000).Verdict; v != Aligned {
		t.Fatal(v)
	}
}
