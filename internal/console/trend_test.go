package console

import (
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/store"
)

func TestBuildTrend(t *testing.T) {
	cfg := testConfig(t)
	st := openArchive(t, cfg)
	zone := cfg.Cloudflare.Zones[0]
	now := time.Date(2026, 11, 18, 22, 38, 0, 0, time.UTC)
	hourStart := now.Truncate(time.Hour)
	seed := func(from time.Time, total int64) {
		snap := store.Snapshot{Metrics: analyze.Metrics{Total: total}}
		if err := st.PutSnapshot(zone.ZoneID, store.Hour, from, from.Add(time.Hour), snap); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < trendHours; i++ {
		h := hourStart.Add(-time.Duration(trendHours-i) * time.Hour)
		seed(h, int64(1000*(i+1)))
		seed(h.Add(-24*time.Hour), int64(500*(i+1)))
	}

	// The live view's rolling hour (21:33-22:33) is the "now" point.
	to := now.Add(-liveLag)
	live := &LiveView{From: to.Add(-liveSpan), To: to, Total: 7777}
	html, ok := buildTrend(st, zone, now, time.UTC, live)
	if !ok || html == "" {
		t.Fatal("trend strip not built from a seeded archive")
	}
	s := string(html)
	for _, want := range []string{"l-total", "l-yday", ">16<", ">21<", ">22:33<"} {
		if !strings.Contains(s, want) {
			t.Fatalf("trend chart lacks %q:\n%s", want, s)
		}
	}

	// Without a usable live view the strip ends at the newest closed hour.
	html, ok = buildTrend(st, zone, now, time.UTC, &LiveView{Err: "boom"})
	if !ok || strings.Contains(string(html), "22:") {
		t.Fatalf("failed live view must not add a point:\n%s", html)
	}

	// No archive hours for today: no strip.
	empty := openArchive(t, testConfig(t))
	if _, ok := buildTrend(empty, zone, now, time.UTC, live); ok {
		t.Fatal("trend strip built without any of today's hours")
	}
}
