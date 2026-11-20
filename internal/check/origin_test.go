package check

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// TestVPSOriginDownThenSlow walks a WordPress-on-a-VPS zone (no Worker)
// through an origin outage: 522s from a healthy baseline page at once,
// with the status split and the "origin down" hypothesis; after recovery
// a slow-but-up origin is reported as slow, not as 5xx.
func TestVPSOriginDownThenSlow(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	now := time.Time{}
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	zone := cfg.Cloudflare.Zones[0]
	hour := func(h int) time.Time { return time.Date(2026, 11, 19, h, 0, 0, 0, time.UTC) }
	vps := func() *window {
		w := normal()
		w.origin = &cfapi.OriginStats{Requests: 20_000, TTFBP95: 464, TotalP95: 803, TCPP95: 3, TLSP95: 9}
		return w
	}
	for h := 0; h < 24; h++ {
		api.windows[hour(h).Add(-24*time.Hour)] = vps()
		api.windows[hour(h)] = vps()
	}
	down := vps()
	down.unreach = 340
	down.origin = &cfapi.OriginStats{Requests: 900, TTFBP95: 600, TotalP95: 900}
	api.windows[hour(8)] = down
	slow := vps()
	slow.origin = &cfapi.OriginStats{Requests: 20_000, TTFBP95: 2400, TotalP95: 2900}
	api.windows[hour(12)] = slow

	run := func(at int) {
		t.Helper()
		now = hour(at).Add(7 * time.Minute)
		if err := r.Intraday(context.Background(), zone); err != nil {
			t.Fatal(err)
		}
	}
	run(9)
	if len(out.msgs) != 1 {
		t.Fatalf("want the outage alert, got %d", len(out.msgs))
	}
	for _, want := range []string{"Cloudflare cannot reach the origin", "Cloudflare got no answer from the origin (52x errors): 340", "522 ×340", "origin is down or unreachable", "(P95): first byte 600 ms"} {
		if !strings.Contains(out.msgs[0], want) {
			t.Errorf("outage alert lacks %q:\n%s", want, out.msgs[0])
		}
	}
	t.Logf("outage alert:\n%s", out.msgs[0])
	run(10)
	run(11)
	run(12) // two clean rounds: recovered
	run(13) // the 12:00 hour: up, but slow
	last := out.msgs[len(out.msgs)-1]
	for _, want := range []string{"▶ Origin slower", "time to first byte for the slowest 5% of requests (P95) is 2.4 s (same hour yesterday 464 ms, 5.2×)", "computes slower with load flat", "origin requests by path"} {
		if !strings.Contains(last, want) {
			t.Errorf("slow alert lacks %q:\n%s", want, last)
		}
	}
	t.Logf("slow alert:\n%s", last)
	if strings.Contains(last, "cannot reach the origin") {
		t.Errorf("a slow origin is not an unreachable one:\n%s", last)
	}
}
