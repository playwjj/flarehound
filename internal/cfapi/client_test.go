package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestTopIPWithASN(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[
		{"count":5,"dimensions":{"clientIP":"2001:db8::1","clientAsn":"15169","verifiedBotCategory":"Search Engine Crawler"}},
		{"count":9,"dimensions":{"clientIP":"203.0.113.7","clientAsn":"45102","verifiedBotCategory":""}}]}]}}}`, &q)
	got, err := c.Top(context.Background(), "zone", from, to, DimClientIPASNBot, 50, EdgeBlocked())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, "dimensions{clientIP clientAsn verifiedBotCategory}") || !strings.Contains(q, "edgeResponseStatus:403") {
		t.Errorf("query: %s", q)
	}
	if len(got) != 2 || got[0] != (Face{Name: "203.0.113.7", ASN: 45102, Count: 9}) || got[1].Name != "2001:db8::1" || got[1].ASN != 15169 || got[1].Cat != "Search Engine Crawler" {
		t.Fatalf("faces = %+v", got)
	}
}

func TestClientIPDimAndSplitBots(t *testing.T) {
	full := Caps{Probed: true, HTTPFields: map[string]bool{"dimensions_clientAsn": true, "dimensions_verifiedBotCategory": true}}
	free := Caps{Probed: true, HTTPFields: map[string]bool{"dimensions_verifiedBotCategory": true}}
	if full.ClientIPDim() != DimClientIPASNBot || free.ClientIPDim() != DimClientIPBot || (Caps{Probed: true}).ClientIPDim() != DimClientIP {
		t.Fatal("ClientIPDim")
	}
	others, bots := SplitBots([]Face{{Name: "a", Cat: "x"}, {Name: "b"}, {Name: "c"}, {Name: "d", Cat: "y"}}, 1)
	if len(others) != 1 || others[0].Name != "b" || len(bots) != 2 {
		t.Fatalf("others %+v bots %+v", others, bots)
	}
}

func TestWorkerStats(t *testing.T) {
	c := server(t, `{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[
		{"sum":{"requests":1000},"quantiles":{"cpuTimeP50":4000,"cpuTimeP99":25000}}]}]}}}`, nil)
	st, err := c.WorkerStats(context.Background(), "acct", "web", from, to)
	if err != nil || st.Requests != 1000 || st.CPUP50ms != 4 || st.CPUP99ms != 25 {
		t.Fatalf("%+v err=%v", st, err)
	}
}

func TestMinutes(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptiveGroups":[
		{"count":3,"dimensions":{"datetimeMinute":"2026-11-19T01:07:00Z","clientIP":"45.13.7.7"}},
		{"count":5,"dimensions":{"datetimeMinute":"2026-11-19T01:02:00Z","clientIP":"45.13.7.8"}}]}]}}}`, &q)
	got, err := c.Minutes(context.Background(), "zone", true, from, to, FwDimIP, Filter{FirewallRuleID: "r1"}, 100)
	if err != nil || len(got) != 2 || got[0].Name != "45.13.7.7" || got[0].Count != 3 || !got[0].At.Equal(time.Date(2026, 11, 19, 1, 7, 0, 0, time.UTC)) {
		t.Fatalf("got %+v %v", got, err)
	}
	if !strings.Contains(q, "firewallEventsAdaptiveGroups") || !strings.Contains(q, "datetimeMinute_DESC") || !strings.Contains(q, `ruleId:"r1"`) {
		t.Fatalf("query %s", q)
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

// TestASNIsAString: clientAsn is a String in the GraphQL schema — the
// filter must be quoted (an unquoted number is rejected with "clientAsn:
// not a string"), and dimension values arrive as strings.
func TestASNIsAString(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[
		{"count":9,"dimensions":{"clientAsn":"207990","clientRequestPath":"/a"}}]}]}}}`, &q)
	if _, err := c.Top(context.Background(), "zone", from, to, DimPath, 3, Filter{ASN: 207990}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, `clientAsn:"207990"`) || strings.Contains(q, "clientAsn:207990") {
		t.Fatalf("ASN filter not a string literal: %s", q)
	}

	c = server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[
		{"count":9,"dimensions":{"clientAsn":"15169","clientASNDescription":"GOOGLE"}},
		{"count":5,"dimensions":{"clientAsn":7922,"clientASNDescription":"COMCAST"}}]}]}}}`, nil)
	got, err := c.Top(context.Background(), "zone", from, to, DimASN, 5, Filter{})
	if err != nil || got[0].Name != "AS15169" || got[0].ASN != 15169 || got[1].ASN != 7922 {
		t.Fatalf("string ASN dimension: %+v %v", got, err)
	}
	names, err := c.ASNNames(context.Background(), "zone", from, to, 5)
	if err != nil || names[15169] != "GOOGLE" || names[7922] != "COMCAST" {
		t.Fatalf("names %v %v", names, err)
	}
}

func TestFirewallFromRoundsUpToTheHour(t *testing.T) {
	c := Caps{FirewallEnabled: true, FirewallMaxAge: 72 * time.Hour}
	now := time.Date(2026, 11, 17, 13, 44, 0, 0, time.UTC)
	got := c.FirewallFrom(now.Add(-30*24*time.Hour), now)
	if want := time.Date(2026, 11, 14, 14, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("earliest %s, want %s", got, want)
	}
	if got := c.FirewallFrom(now.Add(-time.Hour), now); !got.Equal(now.Add(-time.Hour)) {
		t.Fatal("windows inside retention must not move")
	}
	if got := (Caps{}).FirewallFrom(now.Add(-100*time.Hour), now); !got.Equal(now.Add(-100 * time.Hour)) {
		t.Fatal("unknown retention leaves the window alone")
	}
}

func TestHourly(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[
		{"count":5,"dimensions":{"datetimeHour":"2026-11-17T08:00:00Z"}},
		{"count":7,"dimensions":{"datetimeHour":"2026-11-17T09:00:00Z"}}]}]}}}`, &q)
	got, err := c.Hourly(context.Background(), "zone", from, to, Filter{CacheStatus: "dynamic"})
	if err != nil || got[from] != 5 || got[from.Add(time.Hour)] != 7 || !strings.Contains(q, "datetimeHour") {
		t.Fatalf("%v %v %s", got, err, q)
	}
}

func TestReadRetriesWriteDoesNot(t *testing.T) {
	old := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { retryDelays = old }()

	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/graphql") {
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), "query") {
				t.Errorf("retried GraphQL request lost its body: %q", b)
			}
			_, _ = w.Write([]byte(`{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[{"count":7}]}]}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	}))
	defer srv.Close()

	c := New("t")
	c.endpoint = srv.URL + "/graphql"
	if _, err := c.Count(context.Background(), "z", time.Now().Add(-time.Hour), time.Now(), Filter{}); err != nil {
		t.Fatalf("GraphQL read not retried after a 503: %v", err)
	}
	if n.Load() != 2 {
		t.Fatalf("GraphQL attempts: %d", n.Load())
	}

	n.Store(0)
	r := NewREST("t")
	r.base = srv.URL
	if _, err := r.do(context.Background(), http.MethodPost, "/zones/z/rulesets", map[string]any{"x": 1}, nil); err == nil {
		t.Fatal("write after a 503 reported success")
	}
	if n.Load() != 1 {
		t.Fatalf("a write was retried: %d attempts", n.Load())
	}
	n.Store(0)
	if _, err := r.do(context.Background(), http.MethodGet, "/zones/z", nil, nil); err != nil {
		t.Fatalf("REST read not retried: %v", err)
	}
}

func TestOriginStats(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[{"count":1234,"quantiles":{
		"originResponseHeaderReceiveDurationMsP95":464,"originResponseDurationMsP95":803,
		"originTcpHandshakeDurationMsP95":12,"originTlsHandshakeDurationMsP95":30}}]}]}}}`, &q)
	s, err := c.OriginStats(context.Background(), "zone", from, to)
	if err != nil || s.Requests != 1234 || s.TTFBP95 != 464 || s.TotalP95 != 803 || s.TCPP95 != 12 || s.TLSP95 != 30 {
		t.Fatalf("%+v %v", s, err)
	}
	// Only requests the origin answered: cache hits would pull P95 to 0.
	if !strings.Contains(q, "originResponseStatus_geq:1") || !strings.Contains(q, "originResponseHeaderReceiveDurationMsP95") {
		t.Fatalf("query %s", q)
	}
}

func TestOriginUnreachableFilter(t *testing.T) {
	got := OriginUnreachable().render(from, to)
	if !strings.Contains(got, "edgeResponseStatus_geq:520") || !strings.Contains(got, "edgeResponseStatus_lt:531") {
		t.Fatal(got)
	}
}

func TestSimulatorReads(t *testing.T) {
	var q string
	c := server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[{"count":7}]}]}}}`, &q)
	if _, err := c.Count(context.Background(), "zone", from, to, Filter{Where: `AND:[{clientAsn:"30633"}]`}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, `datetime_lt:"2026-11-17T09:00:00Z",AND:[{clientAsn:"30633"}]`) {
		t.Fatalf("where not appended: %s", q)
	}
	c = server(t, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[
		{"count":5,"dimensions":{"clientAsn":"4134","clientASNDescription":"CHINANET-BACKBONE"}},
		{"count":9,"dimensions":{"clientAsn":"24940","clientASNDescription":"HETZNER-AS"}}]}]}}}`, &q)
	fs, err := c.Top(context.Background(), "zone", from, to, DimASNNamed, 5, Filter{})
	if err != nil || len(fs) != 2 || fs[0].ASN != 24940 || fs[0].Desc != "HETZNER-AS" || fs[0].Name != "AS24940" || fs[1].Desc != "CHINANET-BACKBONE" {
		t.Fatalf("named ASNs: %+v %v", fs, err)
	}
	c = server(t, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptiveGroups":[{"count":3,"dimensions":{"action":"block","ruleId":"r1"}}]}]}}}`, &q)
	fs, err = c.FirewallGroups(context.Background(), "zone", from, to, "action ruleId", 10, Filter{Where: `AND:[{userAgent:"x"}]`})
	if err != nil || len(fs) != 1 || fs[0].Name != "block r1" || !strings.Contains(q, "firewallEventsAdaptiveGroups") {
		t.Fatalf("firewall groups: %+v %v %s", fs, err, q)
	}
}

func TestCapabilitiesFirewallFields(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		queries = append(queries, body["query"])
		if strings.Contains(body["query"], "availableFields}}}}}") && !strings.Contains(body["query"], "httpRequestsAdaptiveGroups") {
			io.WriteString(w, `{"data":{"viewer":{"zones":[{"settings":{"firewallEventsAdaptiveGroups":{"availableFields":["dimensions_action","dimensions_clientAsn"]}}}]}}}`)
			return
		}
		io.WriteString(w, `{"data":{"viewer":{"zones":[{"settings":{
			"httpRequestsAdaptiveGroups":{"enabled":true,"availableFields":["dimensions_clientAsn"]},
			"firewallEventsAdaptiveGroups":{"enabled":true,"notOlderThan":2592000}}}]}}}`)
	}))
	t.Cleanup(srv.Close)
	c := New("tok").WithEndpoint(srv.URL)
	caps, err := c.Capabilities(context.Background(), "zone")
	if err != nil || !caps.HasDim(DimASN) || !caps.HasFirewallDim("clientAsn") || caps.HasFirewallDim("clientRefererHost") {
		t.Fatalf("caps: %+v %v (queries %v)", caps, err, queries)
	}
	if len(queries) != 2 || strings.Contains(queries[0], "firewallEventsAdaptiveGroups{enabled notOlderThan availableFields") {
		t.Fatalf("the main probe must not depend on the firewall field list: %v", queries)
	}
	// The field list failing leaves the main probe intact.
	c2 := server(t, `{"data":{"viewer":{"zones":[{"settings":{
		"httpRequestsAdaptiveGroups":{"enabled":true,"availableFields":["dimensions_clientAsn"]},
		"firewallEventsAdaptiveGroups":{"enabled":true,"notOlderThan":2592000}}}]}}}`, nil)
	caps, err = c2.Capabilities(context.Background(), "zone")
	if err != nil || !caps.Probed || caps.FirewallFields != nil || !caps.HasFirewallDim("clientRefererHost") {
		t.Fatalf("fallback: %+v %v", caps, err)
	}
	free := Caps{Probed: true}
	if free.HasFirewallDim("action") {
		t.Fatal("no firewall dataset, but a firewall dimension")
	}
}
