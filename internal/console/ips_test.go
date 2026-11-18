package console

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

func TestIPKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::9": "2001:db8:1:2::/64",
		"not an address":       "not an address",
	} {
		if got, _ := ipKey(in); got != want {
			t.Errorf("ipKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPAggregation(t *testing.T) {
	cfg := &config.Config{}
	cfg.KnownFaces.ASNs = []int{15169}
	g := newIPAggregator(3)
	g.add([]cfapi.Face{{Name: "203.0.113.7", ASN: 45102, Count: 100}, {Name: "2001:db8:1:2::a", ASN: 8075, Count: 40}, {Name: "2001:db8:1:2::b", ASN: 8075, Count: 30}}, 0)
	g.add([]cfapi.Face{{Name: "203.0.113.7", ASN: 45102, Count: 100}, {Name: "66.249.66.1", ASN: 15169, Count: 900}}, 1)
	g.add([]cfapi.Face{{Name: "198.51.100.2", ASN: 14061, Count: 5000}}, 2)
	g.addBlocked([]cfapi.Face{{Name: "203.0.113.7", Count: 150}, {Name: "192.0.2.1", Count: 999}})
	b := &IPBoard{Total: 10000, SortHours: true}
	g.finish(b, cfg, ipBlocks([]store.BlockEvent{{Type: "ip", Value: "2001:db8:1::/48"}, {Type: "asn", Value: "45102"}}))

	if len(b.Rows) != 3 || len(b.Known) != 1 || b.Known[0].Name != "66.249.66.1" || b.KnownSum != 900 {
		t.Fatalf("rows %+v known %+v", b.Rows, b.Known)
	}
	// Persistence first: two hours beats one hour with far more requests.
	top := b.Rows[0]
	if top.Name != "203.0.113.7" || top.Hours != 2 || !top.Strip[0] || !top.Strip[1] || top.Strip[2] ||
		top.Count != 200 || top.Share != 2 || top.BlockPct != 75 || !top.Drill || top.Listed {
		t.Fatalf("top row %+v", top)
	}
	if b.Rows[1].Name != "198.51.100.2" {
		t.Fatalf("second row %+v", b.Rows[1])
	}
	v6 := b.Rows[2]
	if v6.Name != "2001:db8:1:2::/64" || v6.Members != 2 || v6.Count != 70 || v6.Hours != 1 || v6.Drill ||
		!v6.Listed || v6.Crawler != "Bingbot" {
		t.Fatalf("v6 row %+v", v6)
	}
	// By requests instead.
	b2 := &IPBoard{Total: 10000}
	g.finish(b2, cfg, nil)
	if b2.Rows[0].Name != "198.51.100.2" {
		t.Fatalf("by count: %+v", b2.Rows)
	}
}

// ipAnalytics answers the live IP board.
type ipAnalytics struct{ fakeAnalytics }

func (a *ipAnalytics) Top(ctx context.Context, z string, from, to time.Time, dim string, n int, fl cfapi.Filter) ([]cfapi.Face, error) {
	switch dim {
	case cfapi.DimClientIPASN:
		return []cfapi.Face{{Name: "203.0.113.7", ASN: 45102, Count: 9000}, {Name: "66.249.66.1", ASN: 15169, Count: 800}}, nil
	case cfapi.DimClientIP:
		if fl == cfapi.EdgeBlocked() {
			return []cfapi.Face{{Name: "203.0.113.7", Count: 4500}}, nil
		}
	}
	return a.fakeAnalytics.Top(ctx, z, from, to, dim, n, fl)
}

func TestIPBoardPages(t *testing.T) {
	e := newWriteEnv(t, true)
	e.srv.Analytics = &ipAnalytics{}
	c := e.admin

	// 24 h before any hour has IPs: says so, points at the live hour.
	if _, body, _ := c.do("GET", "/ips", nil, nil); !strings.Contains(body, "No hour with client IPs archived yet") {
		t.Fatalf("empty 24 h:\n%s", body)
	}

	// Archive IPs into the newest three hours.
	latest, ok, _ := e.st.LatestHour(zoneID)
	if !ok {
		t.Fatal("no archive")
	}
	for k := 0; k < 3; k++ {
		from := latest.From.Add(-time.Duration(k) * time.Hour)
		snap, _, _ := e.st.Snapshot(zoneID, store.Hour, from)
		snap.TopIPs = []cfapi.Face{{Name: "203.0.113.7", ASN: 45102, Count: 1000}}
		if k == 0 {
			snap.TopIPs = append(snap.TopIPs, cfapi.Face{Name: "198.51.100.2", ASN: 14061, Count: 8000})
		}
		snap.BlockedIPs = []cfapi.Face{{Name: "203.0.113.7", Count: 500}}
		if err := e.st.PutSnapshot(zoneID, store.Hour, from, from.Add(time.Hour), snap); err != nil {
			t.Fatal(err)
		}
	}
	_, body, _ := c.do("GET", "/ips", nil, nil)
	for _, want := range []string{"3/3", "1/3", "3,000", "50%", "dim=ip&amp;name=203.0.113.7", "type=ip&amp;value=203.0.113.7", "Most persistent"} {
		if !strings.Contains(body, want) {
			t.Fatalf("24 h board lacks %q:\n%s", want, body)
		}
	}
	if strings.Index(body, "203.0.113.7") > strings.Index(body, "198.51.100.2") {
		t.Fatal("24 h board not ranked by persistence")
	}
	if _, body, _ = c.do("GET", "/ips?sort=count", nil, nil); strings.Index(body, "198.51.100.2") > strings.Index(body, "203.0.113.7") {
		t.Fatal("sort=count not ranked by requests")
	}

	// Live hour: known network folded, crawler network labelled.
	_, body, _ = c.do("GET", "/ips?span=1h", nil, nil)
	for _, want := range []string{"203.0.113.7", "9,000", "50%", "Googlebot network"} {
		if !strings.Contains(body, want) {
			t.Fatalf("live board lacks %q:\n%s", want, body)
		}
	}

	// Drill into one address.
	code, body, _ := c.do("GET", "/movers/drill?dim=ip&name=203.0.113.7", nil, nil)
	if code != http.StatusOK || !strings.Contains(body, "/search") || !strings.Contains(body, `href="/ips?z=example.com"`) {
		t.Fatalf("ip drill: %d\n%s", code, body)
	}
	for _, bad := range []string{"/movers/drill?dim=ip&name=2001:db8::/64", "/movers/drill?dim=ip&name=::ffff:1.2.3.4", "/movers/drill?dim=ip&name=x"} {
		if code, _, _ := c.do("GET", bad, nil, nil); code != http.StatusNotFound {
			t.Fatalf("%s: %d", bad, code)
		}
	}
}
