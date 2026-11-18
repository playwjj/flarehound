package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/store"
)

// partialAnalytics answers the trend strip's one Count query.
type partialAnalytics struct{ from time.Time }

func (p *partialAnalytics) Count(_ context.Context, _ string, from, _ time.Time, _ cfapi.Filter) (int64, error) {
	p.from = from
	return 4242, nil
}

func (p *partialAnalytics) Top(_ context.Context, _ string, _, _ time.Time, _ string, _ int, _ cfapi.Filter) ([]cfapi.Face, error) {
	return nil, nil
}

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

	pa := &partialAnalytics{}
	html, ok := buildTrend(context.Background(), st, pa, zone, now, time.UTC)
	if !ok || html == "" {
		t.Fatal("trend strip not built from a seeded archive")
	}
	s := string(html)
	for _, want := range []string{"l-total", "l-yday", "16", "22"} {
		if !strings.Contains(s, want) {
			t.Fatalf("trend chart lacks %q:\n%s", want, s)
		}
	}
	if !pa.from.Equal(hourStart) {
		t.Fatalf("partial count window starts %v, want the hour in progress %v", pa.from, hourStart)
	}

	// No archive hours for today: no strip.
	empty := openArchive(t, testConfig(t))
	if _, ok := buildTrend(context.Background(), empty, pa, zone, now, time.UTC); ok {
		t.Fatal("trend strip built without any of today's hours")
	}
}
