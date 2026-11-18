package check

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/store"
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
	mu      sync.Mutex
	windows map[time.Time]*window
	reads   map[time.Time]int
	caps    *cfapi.Caps
	asnUsed bool
	// retention, when set, makes RuleHits reject windows starting more
	// than that long before now (a zone keeping 3 days of events).
	retention time.Duration
	now       time.Time
	firewall  []cfapi.Face
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
	case flt.CacheStatus == "dynamic" && flt.PathLike != "":
		return w.dynamic / 10, nil
	case flt.PathLike != "":
		return w.total / 10, nil
	case flt.CacheStatus == "dynamic":
		return w.dynamic, nil
	case flt.OriginStatusFrom == 500:
		return w.o5xx, nil
	case flt == cfapi.Filter{}:
		f.mu.Lock()
		f.reads[from]++
		n := f.reads[from]
		f.mu.Unlock()
		if n > 1 && w.totalAfterSettle > 0 {
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
	case cfapi.DimVerifiedBot:
		if strings.Contains(flt.UserAgent, "Googlebot") {
			return []cfapi.Face{{Name: "Search Engine Crawler", Count: 9000}}, nil
		}
		return []cfapi.Face{{Name: "", Count: 9000}}, nil
	case cfapi.DimASN:
		f.mu.Lock()
		f.asnUsed = true
		f.mu.Unlock()
		if strings.Contains(flt.UserAgent, "Googlebot") {
			return []cfapi.Face{{Name: "AS15169", ASN: 15169, Count: 9000}}, nil
		}
		return w.asn, nil
	case cfapi.DimCacheStatus:
		return []cfapi.Face{{Name: "dynamic", Count: w.dynamic}, {Name: "hit", Count: w.total - w.dynamic}}, nil
	case cfapi.DimClientIP:
		if flt == cfapi.EdgeBlocked() {
			return []cfapi.Face{{Name: "45.13.7.7", Count: 120}}, nil
		}
		return []cfapi.Face{{Name: "45.13.7.7", Count: 300}, {Name: "45.13.7.9", Count: 200}}, nil
	case cfapi.DimClientIPASNBot:
		return []cfapi.Face{{Name: "66.249.66.1", ASN: 15169, Count: 900, Cat: "Search Engine Crawler"},
			{Name: "45.13.7.7", ASN: 207990, Count: 300}, {Name: "45.13.7.9", ASN: 207990, Count: 200}}, nil
	case cfapi.DimPath:
		return []cfapi.Face{{Name: "/rank", Count: w.dynamic / 2}}, nil
	}
	return nil, nil
}

func (f *fakeAPI) FirewallByRule(context.Context, string, time.Time, time.Time, int) ([]cfapi.Face, error) {
	return f.firewall, nil
}

func (f *fakeAPI) ASNNames(context.Context, string, time.Time, time.Time, int) (map[int]string, error) {
	return map[int]string{207990: "EXAMPLE-HOSTING-AS", 4134: "CHINANET-BACKBONE"}, nil
}

func (f *fakeAPI) FirewallTop(_ context.Context, _ string, _, _ time.Time, ruleID, _ string, _ int) ([]cfapi.Face, error) {
	if ruleID == "rule-asn" {
		return []cfapi.Face{{Name: "AS207990", ASN: 207990, Count: 120}, {Name: "AS1", ASN: 1, Count: 5}}, nil
	}
	return nil, nil
}

func (f *fakeAPI) MitigatedIPs(context.Context, string, time.Time, time.Time, int) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "45.13.7.7", Count: 812}, {Name: "45.13.7.9", Count: 40}}, nil
}

func (f *fakeAPI) RuleHits(_ context.Context, _ string, from, _ time.Time) (map[string]int64, error) {
	if f.retention > 0 && from.Before(f.now.Add(-f.retention)) {
		return nil, fmt.Errorf("cannot request data older than %s", f.retention)
	}
	return map[string]int64{"r-login": 10}, nil
}

func (f *fakeAPI) Hourly(_ context.Context, _ string, from, to time.Time, _ cfapi.Filter) (map[time.Time]int64, error) {
	out := map[time.Time]int64{}
	for h := from; h.Before(to); h = h.Add(time.Hour) {
		out[h] = 100_000 + int64(h.Hour())*1000
	}
	return out, nil
}

func (f *fakeAPI) DashboardDay(context.Context, string, time.Time) (cfapi.Dashboard, error) {
	return cfapi.Dashboard{Requests: 75_000, Cached: 50_000, Edge5xx: 10}, nil
}

func (f *fakeAPI) Sampling(_ context.Context, _ string, from, _ time.Time) (int64, float64, error) {
	return 100_000, 1, nil
}

func (f *fakeAPI) Capabilities(context.Context, string) (cfapi.Caps, error) {
	if f.caps != nil {
		return *f.caps, nil
	}
	return cfapi.AllCaps(), nil
}

func (f *fakeAPI) WorkerStats(_ context.Context, _, _ string, from, _ time.Time) (int64, float64, error) {
	w := f.w(from)
	return w.calls, w.cpu, nil
}

type sink struct {
	msgs []string
	meta []notify.Message
}

func (s *sink) Send(_ context.Context, m notify.Message) error {
	s.msgs = append(s.msgs, m.Text)
	s.meta = append(s.meta, m)
	return nil
}

func testConfig(t *testing.T) *config.Config {
	cfg := &config.Config{Thresholds: config.DefaultThresholds(), StateFile: filepath.Join(t.TempDir(), "state.json"), Location: time.UTC}
	cfg.Cloudflare.AccountID = strings.Repeat("a", 32)
	cfg.Cloudflare.Zones = []config.Zone{{ZoneID: strings.Repeat("b", 32), Name: "example.com", Workers: []string{"web"}}}
	cfg.Schedule.IntradayInterval, cfg.Schedule.IntradayOffset, cfg.Schedule.SettleDelay = "1h", "7m", "3m"
	cfg.Schedule.DailyReportAt = "08:00"
	cfg.Report.Language = "en"
	cfg.Report.Visuals = true
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
		"Block AS207990 (EXAMPLE-HOSTING-AS, hosting network)", "(ip.geoip.asnum in {207990}) and not cf.client.bot", "Rate-limit /rank", "rollback:",
		"one-click: flarehound block asn 207990 --action block --for 24h",
		"one-click: flarehound ratelimit add --path /rank --requests 20 --period 10"} {
		if !strings.Contains(alert, want) {
			t.Errorf("alert lacks %q:\n%s", want, alert)
		}
	}

	if m := out.meta[0]; m.Kind != "intraday" || m.Decision != "alert" || m.Zone != "example.com" || len(m.Rules) != 5 || !m.WindowTo.Equal(hour(9)) {
		t.Errorf("structured message: %+v", m)
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
	for _, want := range []string{"FlareHound 日报", "越线", "AS207990 45,000 [新]", "固定检查点", "登录", "口径：FlareHound 请求数 ≈ 面板的 1.33 倍"} {
		if !strings.Contains(msg, want) {
			t.Errorf("daily lacks %q:\n%s", want, msg)
		}
	}
}

func withStore(t *testing.T, r *Runner) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "archive.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r.Store = st
	r.Cfg.Archive.HourlyRetentionDays = 400
	return st
}

// TestLongBaselineSuppressesOddYesterday: yesterday was unusually quiet,
// so today's ordinary traffic looks like +50% — but against the 4-week
// median it is normal, and the archive keeps the watch quiet.
func TestLongBaselineSuppressesOddYesterday(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	zone := cfg.Cloudflare.Zones[0]

	quiet := normal()
	quiet.total, quiet.dynamic = 66_000, 26_000
	api.windows[from.Add(-24*time.Hour)] = quiet
	api.windows[from] = normal()

	// Without the archive: false alarm.
	if err := r.Intraday(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 1 {
		t.Fatalf("expected the yesterday-only comparison to fire, got %d msgs", len(out.msgs))
	}

	// With 4 weeks of archived normal days: quiet.
	out.msgs = nil
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	st := withStore(t, r)
	for k := 2; k <= 28; k++ {
		d := from.Add(-time.Duration(k) * 24 * time.Hour)
		if err := st.PutSnapshot(zone.ZoneID, store.Hour, d, d.Add(time.Hour), store.Snapshot{Metrics: analyzeMetrics(normal())}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Intraday(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 0 {
		t.Fatalf("long baseline did not suppress the odd-yesterday alarm:\n%s", out.msgs[0])
	}
	// The round itself was archived, baseline window included, with the
	// hour's client IPs (and their network) for the console's IP board.
	snap, ok, _ := st.Snapshot(zone.ZoneID, store.Hour, from)
	if !ok {
		t.Fatal("current window not archived")
	}
	if len(snap.TopIPs) != 2 || snap.TopIPs[0].Name != "45.13.7.7" || snap.TopIPs[0].ASN != 207990 ||
		len(snap.BlockedIPs) != 1 || snap.BlockedIPs[0].Count != 120 || len(snap.BotIPs) != 1 || snap.BotIPs[0].Name != "66.249.66.1" {
		t.Fatalf("archived IPs: top %+v blocked %+v bots %+v", snap.TopIPs, snap.BlockedIPs, snap.BotIPs)
	}
	if _, ok, _ := st.Snapshot(zone.ZoneID, store.Hour, from.Add(-24*time.Hour)); !ok {
		t.Fatal("baseline window not archived")
	}
}

func analyzeMetrics(w *window) analyze.Metrics {
	return analyze.Metrics{Total: w.total, Dynamic: w.dynamic, Origin5xx: w.o5xx, TopUA: w.ua, TopASN: w.asn}
}

func TestArchiveAnnotatesAndRecords(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	st := withStore(t, r)
	zone := cfg.Cloudflare.Zones[0]
	api.windows[from.Add(-24*time.Hour)] = normal()
	api.windows[from] = surge()
	if err := r.Intraday(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 1 || !strings.Contains(out.msgs[0], "first-seen not judged") {
		t.Fatalf("got %v", out.msgs)
	}
	as, _ := st.Alerts(zone.ZoneID, from, from.Add(2*time.Hour))
	if len(as) != 1 || as[0].Decision != "alert" {
		t.Fatalf("alert history = %+v", as)
	}
	if rec, ok, _ := st.Face(zone.ZoneID, store.DimASN, "AS207990"); !ok || !rec.FirstSeen.Equal(from) {
		t.Fatalf("face not recorded: %+v", rec)
	}
}

func TestBackfill(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	now := time.Date(2026, 11, 17, 8, 7, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: &sink{}, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	st := withStore(t, r)
	zone := cfg.Cloudflare.Zones[0]
	if err := r.Backfill(context.Background(), zone, 2, 0); err != nil {
		t.Fatal(err)
	}
	s, _ := st.Stats(zone.ZoneID)
	if s.Hours != 48 {
		t.Fatalf("backfilled %d hours, want 48", s.Hours)
	}
	// Second run fetches nothing new.
	api.reads = map[time.Time]int{}
	if err := r.Backfill(context.Background(), zone, 2, 0); err != nil {
		t.Fatal(err)
	}
	if len(api.reads) != 0 {
		t.Fatalf("re-fetched %d archived windows", len(api.reads))
	}
}

func TestDailyShowsBlocks(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	end := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return end.Add(7 * time.Minute) }}
	st := withStore(t, r)
	zone := cfg.Cloudflare.Zones[0]
	api.windows[end.Add(-48*time.Hour)] = normal()
	api.windows[end.Add(-24*time.Hour)] = normal()
	_ = st.AddBlockEvent(store.BlockEvent{At: end.Add(-5 * time.Hour), Zone: zone.ZoneID, Op: "block", Type: "asn", Value: "207990",
		Action: "challenge", Mechanism: "custom_rule", RuleID: "rule-asn", ExpiresAt: end.Add(19 * time.Hour), Actor: "cli"})
	if err := r.Daily(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.msgs[0], "AS207990 (challenge): 120") || !strings.Contains(out.msgs[0], "expires 11-18 03:00") ||
		!strings.Contains(out.msgs[0], "45.13.7.7: 812") {
		t.Fatalf("daily lacks block checkpoint:\n%s", out.msgs[0])
	}
}

// TestFreePlanDegrades: no clientAsn, no firewall dataset (Cloudflare
// Free). The round must still run, never query unavailable fields, and
// verify crawlers through verifiedBotCategory.
func TestFreePlanDegrades(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	caps := cfapi.Caps{Probed: true, HTTPFields: map[string]bool{
		"dimensions_userAgent": true, "dimensions_clientIP": true, "dimensions_cacheStatus": true,
		"dimensions_clientRequestPath": true, "dimensions_verifiedBotCategory": true}}
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}, caps: &caps}
	out := &sink{}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	api.windows[from.Add(-24*time.Hour)] = normal()
	cur := surge()
	cur.ua = append(cur.ua, cfapi.Face{Name: "Mozilla/5.0 (compatible; Googlebot/2.2)", Count: 9000})
	api.windows[from] = cur
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if api.asnUsed {
		t.Fatal("queried clientAsn on a plan without it")
	}
	if len(out.msgs) != 1 || strings.Contains(out.msgs[0], "New user agent") || !strings.Contains(out.msgs[0], "verified crawlers") {
		t.Fatalf("got %v", out.msgs)
	}
	out.msgs = nil
	if err := r.Daily(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.msgs[0], "not available on this plan") || !strings.Contains(out.msgs[0], "unavailable (plan or token permission)") {
		t.Fatalf("daily:\n%s", out.msgs[0])
	}
}

// TestImpostorAndYoungArchive: a "Googlebot" Cloudflare does not verify is
// named as an impostor; with a one-day archive, new faces are not
// labelled "never seen before".
func TestImpostorAndYoungArchive(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	caps := cfapi.Caps{Probed: true, HTTPFields: map[string]bool{
		"dimensions_userAgent": true, "dimensions_clientIP": true, "dimensions_cacheStatus": true,
		"dimensions_clientRequestPath": true, "dimensions_verifiedBotCategory": true}}
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}, caps: &caps}
	out := &sink{}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	withStore(t, r)
	api.windows[from.Add(-24*time.Hour)] = normal()
	cur := surge()
	cur.ua = append(cur.ua, cfapi.Face{Name: "Mozilla/5.0 (compatible; Bingbot/2.0)", Count: 30_000})
	api.windows[from] = cur
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	msg := out.msgs[0]
	if !strings.Contains(msg, "IMPOSTOR") || !strings.Contains(msg, "claims to be Bingbot") {
		t.Errorf("impostor not named:\n%s", msg)
	}
	if strings.Contains(msg, "never seen before") || !strings.Contains(msg, "first-seen not judged") {
		t.Errorf("young archive still claims first-seen:\n%s", msg)
	}
}

func TestLabelRules(t *testing.T) {
	cfg := testConfig(t)
	cfg.RuleNames = map[string]string{"a3c36f59e1d2": "WordPress probes"}
	r := &Runner{Cfg: cfg}
	in := []cfapi.Face{{Name: "block firewallCustom:a3c36f59e1d2", Count: 9}, {Name: "block firewallCustom:other", Count: 1}}
	got := r.labelRules(cfg.Cloudflare.Zones[0], in)
	if got[0].Name != "block firewallCustom:WordPress probes (a3c36f59)" || got[1].Name != in[1].Name {
		t.Fatalf("got %+v", got)
	}
	if in[0].Name != "block firewallCustom:a3c36f59e1d2" {
		t.Fatal("input mutated (the archive must keep raw IDs)")
	}
}

func TestPathRuleDynamicOnly(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	cfg.PathRules = []config.PathRule{{Name: "all", Path: "/v1/social-account/*"}, {Name: "dyn", Path: "/v1/social-account/*", DynamicOnly: true}}
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	r := &Runner{API: api, Cfg: cfg}
	w := normal()
	api.windows[time.Time{}] = w
	m, err := r.fetch(context.Background(), cfg.Cloudflare.Zones[0], schedule.Window{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if m.Paths["all"] != w.total/10 || m.Paths["dyn"] != w.dynamic/10 {
		t.Fatalf("paths %+v", m.Paths)
	}
}

type fakeRules struct {
	rs     cfapi.Ruleset
	denied bool
}

func (f *fakeRules) Entrypoint(context.Context, string) (cfapi.Ruleset, bool, error) {
	if f.denied {
		return cfapi.Ruleset{}, false, &cfapi.APIError{Status: 403, Code: 10000, Message: "Authentication error"}
	}
	return f.rs, true, nil
}
func (f *fakeRules) AccessRules(context.Context, string, string) ([]cfapi.AccessRule, error) {
	return nil, &cfapi.APIError{Status: 403, Code: 10000}
}
func (f *fakeRules) ZonePlan(context.Context, string) (string, error) { return "free", nil }

func auditRules(version string) cfapi.Ruleset {
	old := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	return cfapi.Ruleset{ID: "rs", Version: version, Rules: []cfapi.Rule{
		{ID: "r-skip", Action: "skip", Description: "let monitors in", Enabled: true, LastUpdated: old,
			Expression: `http.user_agent contains "Monitor"`, ActionParameters: &cfapi.ActionParameters{Ruleset: "current"}},
		{ID: "r-login", Action: "managed_challenge", Description: "challenge login", Enabled: true, LastUpdated: old,
			Expression: `starts_with(http.request.uri.path, "/login")`},
	}}
}

func TestAuditInDailyAndOnRulesetChange(t *testing.T) {
	cfg := testConfig(t)
	cfg.Report.Language = "en"
	cfg.WAFAudit.SensitivePaths = []string{"/login*", "/search*"}
	cfg.RuleNames = nil
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	rules := &fakeRules{rs: auditRules("7")}
	out := &sink{}
	end := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	now := end.Add(7 * time.Minute)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Rules: rules, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	zone := cfg.Cloudflare.Zones[0]
	for h := -48; h < 24; h++ {
		api.windows[end.Add(time.Duration(h)*time.Hour)] = normal()
	}

	if err := r.Daily(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	msg := out.msgs[0]
	for _, want := range []string{"WAF audit: 2 custom rules", "⚠ /search*: no challenge/block rule covers it\n",
		"may exempt", "anyone can forge it", "sits ahead of 1 protective rule(s) (#2)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("daily lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "zombie") {
		t.Errorf("rule with hits called a zombie:\n%s", msg)
	}

	// Intraday rounds: first records the version, a change re-audits.
	out.msgs, out.meta = nil, nil
	if err := r.Intraday(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 0 {
		t.Fatalf("first version must only be recorded: %v", out.msgs)
	}
	rules.rs = auditRules("8")
	now = now.Add(time.Hour)
	if err := r.Intraday(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if len(out.meta) != 1 || out.meta[0].Kind != "audit" || !strings.Contains(out.msgs[0], "version 7 → 8") {
		t.Fatalf("re-audit: %+v", out.meta)
	}
}

func TestAuditWithoutPermission(t *testing.T) {
	cfg := testConfig(t)
	r := &Runner{API: &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}, Cfg: cfg, Rules: &fakeRules{denied: true}}
	d, err := r.Audit(context.Background(), cfg.Cloudflare.Zones[0])
	if err != nil || !strings.Contains(d.NA, "WAF: Read") {
		t.Fatalf("%+v %v", d, err)
	}
}

type lockedSink struct {
	mu  sync.Mutex
	got map[string]int
}

func (s *lockedSink) Send(_ context.Context, m notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got[m.Zone]++
	return nil
}

// TestParallelZones runs six zones three at a time against one shared
// runner (run with -race): every zone alerts exactly once, state files
// stay separate, and one failing zone does not stop the others.
func TestParallelZones(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones = nil
	for i := 0; i < 6; i++ {
		cfg.Cloudflare.Zones = append(cfg.Cloudflare.Zones, config.Zone{ZoneID: fmt.Sprintf("%032d", i), Name: fmt.Sprintf("z%d.example", i), Workers: []string{"web"}})
	}
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	api.windows[from.Add(-24*time.Hour)] = normal()
	api.windows[from] = surge()
	out := &lockedSink{got: map[string]int{}}
	r := &Runner{API: api, Cfg: cfg, Sender: out, Rules: &fakeRules{rs: auditRules("1")},
		Now: func() time.Time { return from.Add(67 * time.Minute) }}
	withStore(t, r)

	var active, peak int32
	var mu sync.Mutex
	errs := Parallel(context.Background(), cfg.Cloudflare.Zones, 3, func(ctx context.Context, z config.Zone) error {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		defer func() { mu.Lock(); active--; mu.Unlock() }()
		if z.Name == "z5.example" {
			return fmt.Errorf("boom")
		}
		return r.Intraday(ctx, z)
	})
	for i, err := range errs {
		if (i == 5) != (err != nil) {
			t.Fatalf("zone %d: %v", i, err)
		}
	}
	if peak > 3 {
		t.Fatalf("ran %d at once, limit 3", peak)
	}
	for i := 0; i < 5; i++ {
		if out.got[fmt.Sprintf("z%d.example", i)] != 1 {
			t.Fatalf("alerts per zone: %v", out.got)
		}
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(StatePath(cfg, cfg.Cloudflare.Zones[i])); err != nil {
			t.Fatalf("state file for zone %d: %v", i, err)
		}
	}
}

func TestCalibration(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	now := time.Date(2026, 11, 17, 8, 7, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Now: func() time.Time { return now }}
	st := withStore(t, r)
	s, err := r.Calibrate(context.Background(), cfg.Cloudflare.Zones[0], 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Days) != 3 || s.Requests < 1.33 || s.Requests > 1.34 || s.MinCountDash != 750 {
		t.Fatalf("%+v", s)
	}
	rows, _ := st.CalibrationDays(cfg.Cloudflare.Zones[0].ZoneID, 10)
	if len(rows) != 3 {
		t.Fatalf("stored %d days", len(rows))
	}
	// already-stored days are not re-queried
	r.API = nil
	if _, err := r.Calibrate(context.Background(), cfg.Cloudflare.Zones[0], 3); err != nil {
		t.Fatal(err)
	}
}

// TestRuleHitsRespectRetention: a zone that keeps 3 days of firewall
// events. The 30-day hit window must be clamped (an unclamped window got
// the whole query rejected), and three quiet days must not make zombies.
func TestRuleHitsRespectRetention(t *testing.T) {
	cfg := testConfig(t)
	now := time.Date(2026, 11, 17, 8, 7, 0, 0, time.UTC)
	caps := cfapi.Caps{FirewallEnabled: true, FirewallMaxAge: 72 * time.Hour}
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}, caps: &caps, retention: 72 * time.Hour, now: now}
	r := &Runner{API: api, Cfg: cfg, Rules: &fakeRules{rs: auditRules("1")}, Now: func() time.Time { return now }}
	hits, days := r.ruleHits(context.Background(), cfg.Cloudflare.Zones[0])
	if hits == nil || days != 3 {
		t.Fatalf("hits %v days %d", hits, days)
	}
	d, err := r.Audit(context.Background(), cfg.Cloudflare.Zones[0])
	if err != nil || d.Result.HitsNA || d.Result.HitsDays != 3 || len(d.Result.Zombies) != 0 {
		t.Fatalf("audit %+v %v", d.Result, err)
	}
	if !strings.Contains(report.Audit("en", d, ""), "cover only 3 day(s)") {
		t.Fatal("coverage not reported")
	}
}

func TestDryRunLeavesNoTrace(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	api.windows[from.Add(-24*time.Hour)] = normal()
	api.windows[from] = surge()
	out := &sink{}
	r := &Runner{API: api, Cfg: cfg, Sender: out, DryRun: true, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	st := withStore(t, r)
	for i := 0; i < 2; i++ { // the same window twice: both print, nothing is consumed
		if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
			t.Fatal(err)
		}
	}
	if len(out.msgs) != 2 {
		t.Fatalf("dry runs printed %d messages, want 2", len(out.msgs))
	}
	if _, err := os.Stat(cfg.StateFile); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the state file")
	}
	if as, _ := st.Alerts(cfg.Cloudflare.Zones[0].ZoneID, from, from.Add(24*time.Hour)); len(as) != 0 {
		t.Fatal("dry run recorded alert history")
	}
}

// TestRuleHitsKeepNewerDaysOnRejection: if the oldest day is still
// rejected, the newer days are kept and coverage says so.
func TestRuleHitsKeepNewerDaysOnRejection(t *testing.T) {
	cfg := testConfig(t)
	now := time.Date(2026, 11, 17, 8, 7, 0, 0, time.UTC)
	caps := cfapi.Caps{FirewallEnabled: true} // retention unknown: no clamp
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}, caps: &caps, retention: 50 * time.Hour, now: now}
	r := &Runner{API: api, Cfg: cfg, Now: func() time.Time { return now }}
	hits, days := r.ruleHits(context.Background(), cfg.Cloudflare.Zones[0])
	if hits == nil || days != 2 || hits["r-login"].D30 != 20 {
		t.Fatalf("hits %v days %d", hits, days)
	}
}

// TestFirstAlertLabelsRules: the first round after a start reads the
// ruleset before rendering, so firewall events carry rule names at once.
func TestFirstAlertLabelsRules(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cloudflare.Zones[0].Workers = nil
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}, firewall: []cfapi.Face{{Name: "block firewallCustom:r-login", Count: 9}}}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	api.windows[from.Add(-24*time.Hour)] = normal()
	api.windows[from] = surge()
	out := &sink{}
	r := &Runner{API: api, Cfg: cfg, Sender: out, Rules: &fakeRules{rs: auditRules("1")}, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.msgs[0], "firewallCustom:challenge login (r-login)") {
		t.Fatalf("first alert not labelled:\n%s", out.msgs[0])
	}
}

func TestMessagesCarryVisuals(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	api.windows[from.Add(-24*time.Hour)] = normal()
	api.windows[from] = surge()
	out := &sink{}
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) }}
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	m := out.meta[0]
	if len(m.Images) != 2 || m.Images[0].Name != "requests" || m.Images[1].Name != "dynamic" || len(m.Images[0].PNG) < 1000 {
		t.Fatalf("images %d", len(m.Images))
	}
	if !strings.Contains(m.HTML, `src="cid:requests"`) || !strings.Contains(m.HTML, "Full report") {
		t.Fatal("html missing chart or report")
	}
	cfg.Report.Visuals = false
	out.meta = nil
	cfg.StateFile = filepath.Join(t.TempDir(), "s.json")
	if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	if m := out.meta[0]; m.HTML != "" || len(m.Images) != 0 {
		t.Fatal("visuals off must send text only")
	}
}

// TestAuditScopePerZone: with several zones, each zone's coverage uses its
// own hosts and sensitive paths; a zone without its own list is "not
// configured" instead of being scored against another zone's paths.
func TestAuditScopePerZone(t *testing.T) {
	cfg := testConfig(t)
	cfg.Report.Language = "en"
	cfg.PathRules = nil
	cfg.Daily.Paths = nil
	cfg.WAFAudit.Hosts = []string{"example.com", "www.example.com", "api.other.org"}
	cfg.WAFAudit.SensitivePaths = []string{"/login*", "/ranking*"}
	main := cfg.Cloudflare.Zones[0]
	wp := config.Zone{ZoneID: strings.Repeat("c", 32), Name: "blog.test",
		WAFAudit: &config.ZoneAudit{SensitivePaths: []string{"/wp-login.php", "/xmlrpc.php", "/wp-login.php"}}}
	bare := config.Zone{ZoneID: strings.Repeat("d", 32), Name: "third.test"}
	cfg.Cloudflare.Zones = []config.Zone{main, wp, bare}
	r := &Runner{API: &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}, Cfg: cfg,
		Rules: &fakeRules{rs: auditRules("1")}, Now: func() time.Time { return time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC) }}

	probed := func(d report.AuditData) (hosts, paths map[string]bool) {
		hosts, paths = map[string]bool{}, map[string]bool{}
		for _, c := range d.Result.Coverage {
			hosts[c.Host], paths[c.Path.Pattern] = true, true
		}
		return
	}

	d, err := r.Audit(context.Background(), main)
	if err != nil || d.PathsUnset {
		t.Fatalf("main: %+v %v", d, err)
	}
	h, p := probed(d)
	if len(h) != 2 || !h["www.example.com"] || h["api.other.org"] || len(p) != 2 || !p["/ranking*"] {
		t.Errorf("main zone probes %v × %v", h, p)
	}

	d, _ = r.Audit(context.Background(), wp)
	h, p = probed(d)
	if d.PathsUnset || len(h) != 1 || !h["blog.test"] || len(p) != 2 || p["/login*"] || !p["/xmlrpc.php"] {
		t.Errorf("own list: unset=%v %v × %v", d.PathsUnset, h, p)
	}

	d, _ = r.Audit(context.Background(), bare)
	if !d.PathsUnset || len(d.Result.Coverage) != 0 {
		t.Fatalf("zone without a list must not borrow one: %+v", d)
	}
	txt := report.Audit("en", d, "")
	if !strings.Contains(txt, "not configured for this zone") || strings.Contains(txt, "/ranking") {
		t.Errorf("audit text:\n%s", txt)
	}

	// No global hosts: the default list belongs to the first zone only.
	cfg.WAFAudit.Hosts = nil
	if d, _ = r.Audit(context.Background(), main); d.PathsUnset {
		t.Error("first zone lost the default list")
	}
	if d, _ = r.Audit(context.Background(), bare); !d.PathsUnset {
		t.Error("second zone took the default list")
	}
	// A single zone always uses it.
	cfg.Cloudflare.Zones = []config.Zone{bare}
	if d, _ = r.Audit(context.Background(), bare); d.PathsUnset || len(d.Result.Coverage) != 2 {
		t.Errorf("single zone: %+v", d)
	}
}
