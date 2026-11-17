package check

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

// window is the fake data for one window, keyed by its start time.
type window struct {
	total, dynamic, o5xx int64
	calls                int64
	cpu                  float64
	ua, asn              []cfapi.Face
	// totalAfterSettle, when set, is what a re-read of Total returns.
	totalAfterSettle int64
}

type fakeAPI struct {
	windows map[time.Time]*window
	reads   map[time.Time]int
}

func (f *fakeAPI) w(from time.Time) *window {
	if w, ok := f.windows[from]; ok {
		return w
	}
	return &window{}
}

func (f *fakeAPI) Count(_ context.Context, _ string, from, _ time.Time, flt cfapi.Filter) (int64, error) {
	w := f.w(from)
	switch {
	case flt.CacheStatus == "dynamic":
		return w.dynamic, nil
	case flt.OriginStatusFrom == 500:
		return w.o5xx, nil
	case flt == cfapi.Filter{}:
		f.reads[from]++
		if f.reads[from] > 1 && w.totalAfterSettle > 0 {
			return w.totalAfterSettle, nil
		}
		return w.total, nil
	}
	return 0, nil
}

func (f *fakeAPI) Top(_ context.Context, _ string, from, _ time.Time, dim string, _ int, flt cfapi.Filter) ([]cfapi.Face, error) {
	w := f.w(from)
	switch dim {
	case cfapi.DimUserAgent:
		return w.ua, nil
	case cfapi.DimASN:
		if strings.Contains(flt.UserAgent, "Googlebot") {
			return []cfapi.Face{{Name: "AS15169", ASN: 15169, Count: 9000}}, nil
		}
		return w.asn, nil
	case cfapi.DimCacheStatus:
		return []cfapi.Face{{Name: "dynamic", Count: w.dynamic}, {Name: "hit", Count: w.total - w.dynamic}}, nil
	case cfapi.DimClientIP:
		return []cfapi.Face{{Name: "203.0.113.7", Count: 300}, {Name: "198.51.100.9", Count: 200}}, nil
	case cfapi.DimPath:
		return []cfapi.Face{{Name: "/rank", Count: w.dynamic / 2}}, nil
	}
	return nil, nil
}

func (f *fakeAPI) FirewallByRule(context.Context, string, time.Time, time.Time, int) ([]cfapi.Face, error) {
	return nil, nil
}

func (f *fakeAPI) ASNNames(context.Context, string, time.Time, time.Time, int) (map[int]string, error) {
	return map[int]string{207990: "EXAMPLE-HOSTING-AS", 4134: "CHINANET-BACKBONE"}, nil
}

func (f *fakeAPI) WorkerStats(_ context.Context, _, _ string, from, _ time.Time) (int64, float64, error) {
	w := f.w(from)
	return w.calls, w.cpu, nil
}

type sink struct{ msgs []string }

func (s *sink) Send(_ context.Context, text string) error { s.msgs = append(s.msgs, text); return nil }

func testConfig(t *testing.T) *config.Config {
	cfg := &config.Config{Thresholds: config.DefaultThresholds(), StateFile: filepath.Join(t.TempDir(), "state.json"), Location: time.UTC}
	cfg.Cloudflare.AccountID = strings.Repeat("a", 32)
	cfg.Cloudflare.Zones = []config.Zone{{ZoneID: strings.Repeat("b", 32), Name: "example.com", Workers: []string{"web"}}}
	cfg.Schedule.IntradayInterval, cfg.Schedule.IntradayOffset, cfg.Schedule.SettleDelay = "1h", "7m", "3m"
	cfg.Schedule.DailyReportAt = "08:00"
	cfg.Report.Language = "en"
	return cfg
}

func normal() *window {
	return &window{
		total: 100_000, dynamic: 40_000, o5xx: 5, calls: 50_000, cpu: 4,
		ua:  []cfapi.Face{{Name: "Mozilla/5.0 Chrome/130", Count: 60_000}},
		asn: []cfapi.Face{{Name: "AS4134", ASN: 4134, Count: 50_000}},
	}
}

func surge() *window {
	w := normal()
	w.total, w.dynamic, w.calls, w.cpu = 152_000, 70_000, 76_000, 6
	w.asn = append(w.asn, cfapi.Face{Name: "AS207990", ASN: 207990, Count: 45_000})
	return w
}

// TestIncidentReplay walks the 2026-11-17 incident through the runner:
// the crawler flood starts at 08:00, continues, grows, then ends.
func TestIncidentReplay(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	now := time.Date(2026, 11, 17, 9, 7, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	zone := cfg.Cloudflare.Zones[0]

	hour := func(h int) time.Time { return time.Date(2026, 11, 17, h, 0, 0, 0, time.UTC) }
	for h := 0; h < 24; h++ {
		api.windows[hour(h).Add(-24*time.Hour)] = normal()
		api.windows[hour(h)] = normal()
	}
	api.windows[hour(8)] = surge()
	api.windows[hour(9)] = surge()
	big := surge()
	big.calls = 100_000
	api.windows[hour(10)] = big

	run := func(at int) {
		t.Helper()
		now = hour(at).Add(7 * time.Minute)
		if err := r.Intraday(context.Background(), zone); err != nil {
			t.Fatal(err)
		}
	}

	run(9) // evaluates 08:00–09:00
	if len(out.msgs) != 1 {
		t.Fatalf("want 1 alert, got %d", len(out.msgs))
	}
	alert := out.msgs[0]
	t.Logf("alert:\n%s", alert)
	for _, want := range []string{"anomaly", "Worker web calls", "AS207990", "Hypotheses", "per-IP blocking will not help", "/rank",
		"Block AS207990 (EXAMPLE-HOSTING-AS, hosting network)", "(ip.geoip.asnum in {207990}) and not cf.client.bot", "Rate-limit /rank", "rollback:"} {
		if !strings.Contains(alert, want) {
			t.Errorf("alert lacks %q:\n%s", want, alert)
		}
	}

	run(9)  // same window again (restart): skipped
	run(10) // same anomaly continues: silent
	if len(out.msgs) != 1 {
		t.Fatalf("duplicate alert: %v", out.msgs[1:])
	}
	run(11) // worker calls 100k >= 76k * 1.25: escalate
	if len(out.msgs) != 2 || !strings.Contains(out.msgs[1], "ESCALATED") {
		t.Fatalf("want escalation, got %v", out.msgs)
	}
	run(12)
	run(13)
	if len(out.msgs) != 3 || !strings.Contains(out.msgs[2], "recovered") {
		t.Fatalf("want recovery after two clean rounds, got %d msgs", len(out.msgs))
	}
}

func TestUnsettledCollapseIsWithheld(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	api.windows[from.Add(-24*time.Hour)] = normal()
	lagging := normal()
	lagging.total = 30_000 // looks like -70%
	lagging.totalAfterSettle = 90_000
	api.windows[from] = lagging

	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 0 {
		t.Fatalf("collapse on unsettled data alerted: %v", out.msgs)
	}

	// A collapse that stays put after the settle delay is real.
	api.reads = map[time.Time]int{}
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	lagging.totalAfterSettle = 30_100
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 1 || !strings.Contains(out.msgs[0], "COLLAPSED") {
		t.Fatalf("settled collapse missed: %v", out.msgs)
	}
}

func TestVerifiedGooglebotIsNotANewFace(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	api.windows[from.Add(-24*time.Hour)] = normal()
	cur := normal()
	cur.ua = append(cur.ua, cfapi.Face{Name: "Mozilla/5.0 (compatible; Googlebot/2.2)", Count: 9000})
	api.windows[from] = cur
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 0 {
		t.Fatalf("verified Googlebot version bump alerted: %v", out.msgs)
	}
}

func TestDailyReport(t *testing.T) {
	cfg := testConfig(t)
	cfg.Report.Language = "zh"
	cfg.Daily.Paths = []config.PathCheckpoint{{Label: "登录", Path: "/login*", Max: 0}}
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	end := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return end.Add(7 * time.Minute) }}
	api.windows[end.Add(-48*time.Hour)] = normal()
	api.windows[end.Add(-24*time.Hour)] = surge()
	if err := r.Daily(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 1 {
		t.Fatalf("daily report not sent")
	}
	msg := out.msgs[0]
	t.Logf("daily:\n%s", msg)
	for _, want := range []string{"FlareHound 日报", "越线", "AS207990 45,000 [新]", "固定检查点", "登录"} {
		if !strings.Contains(msg, want) {
			t.Errorf("daily lacks %q:\n%s", want, msg)
		}
	}
}
