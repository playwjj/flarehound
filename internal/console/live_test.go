package console

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

func TestBlend(t *testing.T) {
	a := analyze.Metrics{Total: 1000, Workers: []analyze.WorkerMetrics{{Name: "w", Calls: 100, CPUP50ms: 2}}}
	b := analyze.Metrics{Total: 3000, Workers: []analyze.WorkerMetrics{{Name: "w", Calls: 300, CPUP50ms: 4}}}
	m := blend(a, b, 0.25)
	if m.Total != 2500 || m.Worker("w").Calls != 250 || m.Worker("w").CPUP50ms != 3.5 {
		t.Fatalf("blend: %+v", m)
	}
}

func TestLiveOverview(t *testing.T) {
	e := newWriteEnv(t, false)
	var calls atomic.Int32
	var fail atomic.Bool
	e.srv.Measure = func(_ context.Context, _ config.Zone, from, to time.Time) (analyze.Metrics, error) {
		calls.Add(1)
		if fail.Load() {
			return analyze.Metrics{}, errors.New("graphql: rate limited")
		}
		if to.Sub(from) != time.Hour || time.Since(to) < liveLag {
			t.Errorf("live window %s–%s", from, to)
		}
		return analyze.Metrics{Total: 30000, Dynamic: 2000, Origin5xx: 3}, nil
	}
	_, body, _ := e.admin.do("GET", "/", nil, nil)
	if !strings.Contains(body, "Last 60 minutes") || !strings.Contains(body, "30,000") || !strings.Contains(body, "&#43;200.0%") {
		t.Fatalf("live tiles missing:\n%s", body)
	}
	if !strings.Contains(body, `<details class="settled">`) {
		t.Fatal("settled hour not tucked away when live works")
	}
	e.admin.do("GET", "/", nil, nil)
	if calls.Load() != 1 {
		t.Fatalf("live view re-queried within a minute: %d calls", calls.Load())
	}

	// A failing live query falls back to the settled hour, visibly.
	e.srv.liveCache = map[string]*liveEntry{}
	fail.Store(true)
	_, body, _ = e.admin.do("GET", "/", nil, nil)
	if !strings.Contains(body, "Live query failed") || strings.Contains(body, `<details class="settled">`) || !strings.Contains(body, "25,000") {
		t.Fatalf("live failure fallback:\n%s", body)
	}
}

// fakeAnalytics answers drill-down queries.
type fakeAnalytics struct{ n atomic.Int32 }

func (f *fakeAnalytics) Count(_ context.Context, _ string, from, _ time.Time, fl cfapi.Filter) (int64, error) {
	f.n.Add(1)
	if time.Since(from) > 20*time.Hour { // yesterday
		return 500, nil
	}
	return 14000, nil
}

func (f *fakeAnalytics) Top(_ context.Context, _ string, from, _ time.Time, dim string, _ int, fl cfapi.Filter) ([]cfapi.Face, error) {
	f.n.Add(1)
	y := time.Since(from) > 20*time.Hour
	switch dim {
	case cfapi.DimPath:
		if y {
			return []cfapi.Face{{Name: "/search", Count: 400}}, nil
		}
		return []cfapi.Face{{Name: "/search", Count: 12000}, {Name: "/p/1", Count: 2000}}, nil
	case cfapi.DimASN:
		return []cfapi.Face{{Name: "AS207990", ASN: 207990, Count: 13000}}, nil
	case cfapi.DimUserAgent:
		return []cfapi.Face{{Name: "Crawler/1.0", Count: 13000}}, nil
	}
	return []cfapi.Face{{Name: "200", Count: 9000}, {Name: "403", Count: 5000}}, nil
}

func TestDrill(t *testing.T) {
	e := newWriteEnv(t, false)
	fa := &fakeAnalytics{}
	e.srv.Analytics = fa
	c := e.admin

	if _, body, _ := c.do("GET", "/movers?dim=ua", nil, nil); !strings.Contains(body, "/movers/drill?z=example.com&amp;dim=ua&amp;name=Crawler%2f1.0") {
		t.Fatal("movers entries do not link to the drill-down")
	}
	code, body, _ := c.do("GET", "/movers/drill?dim=ua&name=Crawler%2F1.0", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("drill: %d", code)
	}
	for _, want := range []string{"/search", "12,000", "85.7%", "403", "dim=asn&amp;name=AS207990", "14,000"} {
		if !strings.Contains(body, want) {
			t.Fatalf("drill page lacks %q:\n%s", want, body)
		}
	}
	n := fa.n.Load()
	c.do("GET", "/movers/drill?dim=ua&name=Crawler%2F1.0", nil, nil)
	if fa.n.Load() != n {
		t.Fatal("drill-down re-queried within its cache time")
	}
	if code, _, _ := c.do("GET", "/movers/drill?dim=asn&name=AS207990", nil, nil); code != http.StatusOK {
		t.Fatalf("drill asn: %d", code)
	}
	for _, bad := range []string{"/movers/drill?dim=foo&name=x", "/movers/drill?dim=path&name=%25", "/movers/drill?dim=asn&name=abc", "/movers/drill?dim=ua"} {
		if code, _, _ := c.do("GET", bad, nil, nil); code != http.StatusNotFound {
			t.Fatalf("%s: %d", bad, code)
		}
	}
	// No live analytics: the page says so instead of failing.
	e.srv.Analytics = nil
	if code, body, _ := c.do("GET", "/movers/drill?dim=ua&name=Crawler%2F1.0", nil, nil); code != http.StatusOK || !strings.Contains(body, "needs live queries") {
		t.Fatalf("drill without analytics: %d", code)
	}
}

func TestLiveErrorRetriedSooner(t *testing.T) {
	e := newWriteEnv(t, false)
	var calls atomic.Int32
	e.srv.Measure = func(context.Context, config.Zone, time.Time, time.Time) (analyze.Metrics, error) {
		calls.Add(1)
		return analyze.Metrics{}, errors.New("TLS handshake timeout")
	}
	base := time.Now()
	e.srv.Now = func() time.Time { return base }
	z := e.srv.Cfg.Cloudflare.Zones[0]
	e.srv.liveView(context.Background(), z)
	e.srv.Now = func() time.Time { return base.Add(15 * time.Second) }
	e.srv.liveView(context.Background(), z)
	if calls.Load() != 2 {
		t.Fatalf("failed live query not retried after 15 s: %d calls", calls.Load())
	}
}
