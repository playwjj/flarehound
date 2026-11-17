package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func server(t *testing.T, reply string, seen *string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token")
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		if seen != nil {
			*seen = body["query"]
		}
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return New("tok").WithEndpoint(srv.URL)
}

var from = time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
var to = from.Add(time.Hour)

func TestCount(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[{"count":42}]}]}}}`, &q)
	n, err := c.Count(context.Background(), "zone", from, to, Filter{CacheStatus: "dynamic"})
	if err != nil || n != 42 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for _, want := range []string{`zoneTag:"zone"`, `datetime_geq:"2026-11-17T08:00:00Z"`, `cacheStatus:"dynamic"`} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q lacks %q", q, want)
		}
	}
}

func TestNoAccessIsNotZero(t *testing.T) {
	c := server(t, `{"data":{"viewer":{"zones":[]}}}`, nil)
	if _, err := c.Count(context.Background(), "zone", from, to, Filter{}); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("want ErrNoAccess, got %v", err)
	}
}

func TestGraphQLError(t *testing.T) {
	c := server(t, `{"data":null,"errors":[{"message":"bad field"}]}`, nil)
	if _, err := c.Count(context.Background(), "zone", from, to, Filter{}); err == nil || !strings.Contains(err.Error(), "bad field") {
		t.Fatalf("got %v", err)
	}
}

func TestTopQuotesUntrustedStrings(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[
		{"count":5,"dimensions":{"clientAsn":15169}},
		{"count":9,"dimensions":{"clientAsn":7922}}]}]}}}`, &q)
	ua := `evil"}) {injected} \ "`
	got, err := c.Top(context.Background(), "zone", from, to, DimASN, 5, Filter{UserAgent: ua})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, `userAgent:"evil\"}) {injected} \\ \""`) {
		t.Errorf("UA not escaped: %s", q)
	}
	if !strings.Contains(q, "orderBy:[count_DESC]") {
		t.Error("Top must order by count")
	}
	if len(got) != 2 || got[0].Name != "AS7922" || got[0].ASN != 7922 || got[1].Count != 5 {
		t.Fatalf("faces = %+v", got)
	}
}

func TestWorkerStats(t *testing.T) {
	c := server(t, `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[
		{"sum":{"requests":1000},"quantiles":{"cpuTimeP50":4000}}]}]}}}`, nil)
	n, cpu, err := c.WorkerStats(context.Background(), "acct", "web", from, to)
	if err != nil || n != 1000 || cpu != 4 {
		t.Fatalf("n=%d cpu=%v err=%v", n, cpu, err)
	}
}

func TestFirewallByRule(t *testing.T) {
	c := server(t, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptiveGroups":[
		{"count":77,"dimensions":{"action":"block","source":"firewallCustom","ruleId":"abc"}}]}]}}}`, nil)
	got, err := c.FirewallByRule(context.Background(), "zone", from, to, 10)
	if err != nil || len(got) != 1 || got[0].Name != "block firewallCustom:abc" || got[0].Count != 77 {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestMitigatedIPs(t *testing.T) {
	c := server(t, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptiveGroups":[
		{"count":50,"dimensions":{"clientIP":"45.13.7.7","action":"block"}},
		{"count":30,"dimensions":{"clientIP":"45.13.7.7","action":"managed_challenge"}},
		{"count":900,"dimensions":{"clientIP":"66.249.66.1","action":"skip"}},
		{"count":60,"dimensions":{"clientIP":"45.13.7.9","action":"block"}}]}]}}}`, nil)
	got, err := c.MitigatedIPs(context.Background(), "zone", from, to, 10)
	if err != nil || len(got) != 2 || got[0].Name != "45.13.7.7" || got[0].Count != 80 || got[1].Count != 60 {
		t.Fatalf("got %+v %v", got, err)
	}
}
