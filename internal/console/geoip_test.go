package console

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/store"
)

func fakeGeo(s string) string {
	switch s {
	case "203.0.113.7", "106.201.104.211":
		return "IN"
	case "198.51.100.2":
		return "US"
	}
	return ""
}

// The IP board, the block review, the blocks page and the block log show
// the IP location; without a library they show none.
func TestIPLocationOnConsole(t *testing.T) {
	e := newWriteEnv(t, true)
	e.srv.Analytics = &ipAnalytics{}
	c := e.admin
	latest, _, _ := e.st.LatestHour(zoneID)
	snap, _, _ := e.st.Snapshot(zoneID, store.Hour, latest.From)
	snap.TopIPs = []cfapi.Face{{Name: "203.0.113.7", ASN: 45102, Count: 1000}, {Name: "198.51.100.2", ASN: 14061, Count: 800}}
	if err := e.st.PutSnapshot(zoneID, store.Hour, latest.From, latest.From.Add(time.Hour), snap); err != nil {
		t.Fatal(err)
	}

	if _, body, _ := c.do("GET", "/ips", nil, nil); strings.Contains(body, `class="geo"`) {
		t.Fatal("IP location shown without a library")
	}

	geoip.UseFunc(fakeGeo)
	defer geoip.Reset()
	_, body, _ := c.do("GET", "/ips", nil, nil)
	for _, want := range []string{`203.0.113.7</a> <span class="geo" title="IP location: India">(IN)</span>`, `title="IP location: United States">(US)`} {
		if !strings.Contains(body, want) {
			t.Fatalf("IP board lacks %q:\n%s", want, body)
		}
	}
	if _, body, _ = c.do("GET", "/movers/drill?dim=ip&name=203.0.113.7", nil, nil); !strings.Contains(body, `(IN)</span></h1>`) {
		t.Fatalf("drill-down heading lacks the IP location:\n%s", body)
	}

	form := url.Values{"type": {"ip"}, "value": {"106.201.104.211"}, "action": {"block"}, "for": {"24h"}}
	body, csrf, tok := e.review(t, c, clone(form))
	for _, want := range []string{"<dt>IP location</dt><dd><b>IN · India</b>", "not where its operator is", "db-ip.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("block review lacks %q:\n%s", want, body)
		}
	}
	ok := clone(form)
	ok.Set("csrf", csrf)
	ok.Set("review", tok)
	if code, body, _ := c.do("POST", "/blocks/apply", ok, nil); code != 303 {
		t.Fatalf("apply: %d\n%s", code, body)
	}
	_, body, _ = c.do("GET", "/blocks", nil, nil)
	if n := strings.Count(body, `title="IP location: India">(IN)`); n < 2 { // active row and the log
		t.Fatalf("blocks page shows the IP location %d time(s):\n%s", n, body)
	}

	// Chinese UI: the name in Chinese.
	c.do("POST", "/lang", url.Values{"csrf": {csrfOf(t, body)}, "lang": {"zh"}}, nil)
	if _, body, _ = c.do("GET", "/ips", nil, nil); !strings.Contains(body, `title="IP 归属地: 印度">(IN)`) {
		t.Fatalf("zh IP board:\n%s", body)
	}
}
