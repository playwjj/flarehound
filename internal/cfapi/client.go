// Package cfapi is a minimal Cloudflare GraphQL Analytics client.
//
// Hard-won rules from production use (SPEC.md section 6):
//   - Keep every query compact and single-dimension: long queries risk
//     truncation somewhere in the chain.
//   - Always orderBy count_DESC; without it, returned groups are arbitrary.
//   - The adaptive dataset has no host or clientCountry dimension and no
//     clientReferer filter. The ASN dimension is clientAsn (lowercase n).
//   - Adaptive counts include Worker subrequests; only ever compare
//     adaptive numbers with adaptive numbers, same window shape.
//
// The package does query assembly and result parsing only — no business
// judgement lives here.
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is the only host the read-only token is ever sent to.
const DefaultEndpoint = "https://api.cloudflare.com/client/v4/graphql"

// ErrNoAccess is returned when the API answers but the zone or account
// is not in the response — almost always a token-permission problem.
// It must never be read as "zero traffic" (that would fake a collapse).
var ErrNoAccess = errors.New("zone/account not visible to this token (check token permissions and IDs)")

type Client struct {
	token    string
	endpoint string
	http     *http.Client
}

func New(token string) *Client {
	return &Client{token: token, endpoint: DefaultEndpoint, http: &http.Client{Timeout: 60 * time.Second}}
}

// WithEndpoint overrides the API endpoint (tests only).
func (c *Client) WithEndpoint(url string) *Client { c.endpoint = url; return c }

// quote renders s as a GraphQL string literal. JSON string escaping is a
// valid subset of GraphQL's, so user agents, paths and script names with
// quotes or backslashes cannot break out of the literal.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Filter narrows a query beyond the time window. Zero values are ignored.
type Filter struct {
	CacheStatus       string // e.g. "dynamic"
	OriginStatusFrom  int    // inclusive
	OriginStatusTo    int    // exclusive
	EdgeStatus        int    // exact edge response status
	EdgeStatusFrom    int    // inclusive
	EdgeStatusTo      int    // exclusive
	PathLike          string // SQL-like pattern, % wildcard
	UserAgent         string // exact
	ASN               int    // exact
	WorkerScript      string // workers dataset only
	FirewallAction    string // firewall dataset only
	FirewallNotAction string // firewall dataset only
	FirewallRuleID    string // firewall dataset only
	ClientIP          string // exact
	UserAgentLike     string // SQL-like pattern, % wildcard
}

func (f Filter) render(from, to time.Time) string {
	parts := []string{"datetime_geq:" + quote(ts(from)), "datetime_lt:" + quote(ts(to))}
	if f.CacheStatus != "" {
		parts = append(parts, "cacheStatus:"+quote(f.CacheStatus))
	}
	if f.OriginStatusFrom > 0 {
		parts = append(parts, fmt.Sprintf("originResponseStatus_geq:%d", f.OriginStatusFrom))
	}
	if f.OriginStatusTo > 0 {
		parts = append(parts, fmt.Sprintf("originResponseStatus_lt:%d", f.OriginStatusTo))
	}
	if f.EdgeStatus > 0 {
		parts = append(parts, fmt.Sprintf("edgeResponseStatus:%d", f.EdgeStatus))
	}
	if f.EdgeStatusFrom > 0 {
		parts = append(parts, fmt.Sprintf("edgeResponseStatus_geq:%d", f.EdgeStatusFrom))
	}
	if f.EdgeStatusTo > 0 {
		parts = append(parts, fmt.Sprintf("edgeResponseStatus_lt:%d", f.EdgeStatusTo))
	}
	if f.PathLike != "" {
		parts = append(parts, "clientRequestPath_like:"+quote(f.PathLike))
	}
	if f.UserAgent != "" {
		parts = append(parts, "userAgent:"+quote(f.UserAgent))
	}
	if f.ASN > 0 {
		// clientAsn is a String in the schema: an unquoted number is
		// rejected ("clientAsn: not a string").
		parts = append(parts, "clientAsn:"+quote(strconv.Itoa(f.ASN)))
	}
	if f.WorkerScript != "" {
		parts = append(parts, "scriptName:"+quote(f.WorkerScript))
	}
	if f.FirewallAction != "" {
		parts = append(parts, "action:"+quote(f.FirewallAction))
	}
	if f.FirewallRuleID != "" {
		parts = append(parts, "ruleId:"+quote(f.FirewallRuleID))
	}
	if f.ClientIP != "" {
		parts = append(parts, "clientIP:"+quote(f.ClientIP))
	}
	if f.UserAgentLike != "" {
		parts = append(parts, "userAgent_like:"+quote(f.UserAgentLike))
	}
	if f.FirewallNotAction != "" {
		parts = append(parts, "action_neq:"+quote(f.FirewallNotAction))
	}
	return strings.Join(parts, ",")
}

// row is one group of any adaptive dataset; dimensions are decoded
// generically so one parser serves every Top-N query.
type row struct {
	Count      int64          `json:"count"`
	Dimensions map[string]any `json:"dimensions"`
	Sum        struct {
		Requests int64 `json:"requests"`
	} `json:"sum"`
	Quantiles struct {
		CPUP50 float64 `json:"cpuTimeP50"` // microseconds
	} `json:"quantiles"`
}

type scope struct {
	HTTP     []row `json:"httpRequestsAdaptiveGroups"`
	Firewall []row `json:"firewallEventsAdaptiveGroups"`
	Workers  []row `json:"workersInvocationsAdaptive"`
}

type gqlResponse struct {
	Data struct {
		Viewer struct {
			Zones    []scope `json:"zones"`
			Accounts []scope `json:"accounts"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *Client) query(ctx context.Context, q string) (*gqlResponse, error) {
	var out gqlResponse
	if err := c.queryInto(ctx, q, &out); err != nil {
		return nil, err
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("cloudflare API: %s", out.Errors[0].Message)
	}
	return &out, nil
}

// queryInto posts a GraphQL query and decodes the whole response into out.
func (c *Client) queryInto(ctx context.Context, q string, out any) error {
	body, _ := json.Marshal(map[string]string{"query": q})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	// Analytics queries only read: a dropped connection, a rate limit or a
	// Cloudflare 5xx is retried a couple of times before it fails a round.
	resp, err := doRetry(ctx, c.http, req, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare API: HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cloudflare API: decode: %w", err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

func (c *Client) zoneRows(ctx context.Context, zoneID, dataset, selection string, limit int, order bool, filter string) ([]row, error) {
	ob := ""
	if order {
		ob = "orderBy:[count_DESC],"
	}
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:%s}){%s(limit:%d,%sfilter:{%s}){%s}}}}`,
		quote(zoneID), dataset, limit, ob, filter, selection)
	r, err := c.query(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(r.Data.Viewer.Zones) == 0 {
		return nil, ErrNoAccess
	}
	z := r.Data.Viewer.Zones[0]
	if dataset == "firewallEventsAdaptiveGroups" {
		return z.Firewall, nil
	}
	return z.HTTP, nil
}

// Count returns the adaptive request count for the window and filter.
func (c *Client) Count(ctx context.Context, zoneID string, from, to time.Time, f Filter) (int64, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups", "count", 1, false, f.render(from, to))
	if err != nil {
		return 0, err
	}
	var n int64
	for _, r := range rows {
		n += r.Count
	}
	return n, nil
}

// Face is one row of a Top-N breakdown (user agent, ASN, path, IP, …).
// Name is the display form ("AS15169" for ASNs); ASN is set for ASN rows.
type Face struct {
	Name  string `json:"name"`
	ASN   int    `json:"asn,omitempty"`
	Count int64  `json:"count"`
}

// Dimension names accepted by Top.
const (
	DimUserAgent   = "userAgent"
	DimASN         = "clientAsn"
	DimPath        = "clientRequestPath"
	DimCacheStatus = "cacheStatus"
	DimClientIP    = "clientIP"
)

// Top returns the Top-N groups of one dimension, ordered by count.
func (c *Client) Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f Filter) ([]Face, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups", "count dimensions{"+dim+"}", limit, true, f.render(from, to))
	if err != nil {
		return nil, err
	}
	return faces(rows, dim), nil
}

// asnOf reads an ASN dimension value, which the API returns as a string
// (it is a String in the schema); numbers are accepted too.
func asnOf(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), x > 0
	case string:
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(x), "AS"))
		return n, err == nil && n > 0
	}
	return 0, false
}

func faces(rows []row, dims ...string) []Face {
	out := make([]Face, 0, len(rows))
	for _, r := range rows {
		var names []string
		face := Face{Count: r.Count}
		for _, d := range dims {
			v := r.Dimensions[d]
			if d == DimASN {
				if n, ok := asnOf(v); ok {
					face.ASN = n
					names = append(names, fmt.Sprintf("AS%d", face.ASN))
					continue
				}
			}
			names = append(names, fmt.Sprint(v))
		}
		face.Name = strings.Join(names, " ")
		out = append(out, face)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// ASNNames returns the Top-N ASNs of the window with their registered
// names (clientASNDescription), used to tell hosting networks from
// eyeball networks. Name lookup is best-effort: callers must cope with
// an error by falling back to the built-in ASN table.
func (c *Client) ASNNames(ctx context.Context, zoneID string, from, to time.Time, limit int) (map[int]string, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups", "count dimensions{clientAsn clientASNDescription}", limit, true, Filter{}.render(from, to))
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, r := range rows {
		n, ok := asnOf(r.Dimensions[DimASN])
		if !ok {
			continue
		}
		if d, ok := r.Dimensions["clientASNDescription"].(string); ok {
			out[n] = d
		}
	}
	return out, nil
}

// nonMitigating firewall actions: the request went through.
var nonMitigating = map[string]bool{"allow": true, "skip": true, "log": true, "bypass": true}

// MitigatedIPs returns the client IPs most often blocked or challenged in
// the window, across every rule (the user's own and FlareHound's) — "is
// the blocked IP still knocking". Requires the firewall dataset.
func (c *Client) MitigatedIPs(ctx context.Context, zoneID string, from, to time.Time, limit int) ([]Face, error) {
	rows, err := c.zoneRows(ctx, zoneID, "firewallEventsAdaptiveGroups", "count dimensions{clientIP action}", 1000, true, Filter{}.render(from, to))
	if err != nil {
		return nil, err
	}
	sum := map[string]int64{}
	for _, r := range rows {
		action, _ := r.Dimensions["action"].(string)
		ip, _ := r.Dimensions["clientIP"].(string)
		if ip == "" || nonMitigating[action] {
			continue
		}
		sum[ip] += r.Count
	}
	out := make([]Face, 0, len(sum))
	for ip, n := range sum {
		out = append(out, Face{Name: ip, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// RuleHits returns firewall-event counts per rule ID in the window.
func (c *Client) RuleHits(ctx context.Context, zoneID string, from, to time.Time) (map[string]int64, error) {
	rows, err := c.zoneRows(ctx, zoneID, "firewallEventsAdaptiveGroups", "count dimensions{ruleId}", 1000, true, Filter{}.render(from, to))
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		if id, _ := r.Dimensions["ruleId"].(string); id != "" {
			out[id] += r.Count
		}
	}
	return out, nil
}

// ASNName returns one ASN's registered name ("" if unknown).
func (c *Client) ASNName(ctx context.Context, zoneID string, from, to time.Time, asn int) (string, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups", "count dimensions{clientAsn clientASNDescription}", 1, true, Filter{ASN: asn}.render(from, to))
	if err != nil || len(rows) == 0 {
		return "", err
	}
	name, _ := rows[0].Dimensions["clientASNDescription"].(string)
	return name, nil
}

// FirewallByRule returns firewall-event counts grouped by rule and action
// ("<action> <source>:<ruleId>"). Not available on every plan: callers
// must treat an error as "data unavailable", not as zero.
func (c *Client) FirewallByRule(ctx context.Context, zoneID string, from, to time.Time, limit int) ([]Face, error) {
	rows, err := c.zoneRows(ctx, zoneID, "firewallEventsAdaptiveGroups", "count dimensions{action source ruleId}", limit, true, Filter{}.render(from, to))
	if err != nil {
		return nil, err
	}
	out := make([]Face, 0, len(rows))
	for _, r := range rows {
		out = append(out, Face{
			Name:  fmt.Sprintf("%v %v:%v", r.Dimensions["action"], r.Dimensions["source"], r.Dimensions["ruleId"]),
			Count: r.Count,
		})
	}
	return out, nil
}

// Caps is a zone's analytics capability profile (SPEC 5 "capability"),
// read from the GraphQL settings node: which dimensions the plan exposes
// and whether the firewall dataset is enabled at all. Free plans, for
// example, have no clientAsn and no firewall events.
type Caps struct {
	HTTPFields      map[string]bool
	FirewallEnabled bool
	// FirewallMaxAge is how far back firewall events can be queried
	// (notOlderThan; 0 = unknown). Queries reaching further are rejected.
	FirewallMaxAge time.Duration
	Probed         bool // false: probing failed, everything is assumed available
}

// retentionMargin keeps queries clear of the retention edge: the edge
// moves while a long run of queries is in flight.
const retentionMargin = 15 * time.Minute

// FirewallFrom clamps the start of a firewall-events window to what the
// zone retains (the dataset rejects windows starting earlier). Zero
// retention (unknown) leaves from unchanged.
func (c Caps) FirewallFrom(from, now time.Time) time.Time {
	if c.FirewallMaxAge <= 0 {
		return from
	}
	// Rounded up to the next full hour: the retention edge has been seen
	// to be enforced on hour boundaries (a window a few minutes past the
	// edge was rejected even though it was inside notOlderThan by the
	// clock).
	earliest := now.Add(-c.FirewallMaxAge + retentionMargin)
	if t := earliest.Truncate(time.Hour); t.Before(earliest) {
		earliest = t.Add(time.Hour)
	}
	if from.Before(earliest) {
		return earliest
	}
	return from
}

// AllCaps is the optimistic profile used when probing fails.
func AllCaps() Caps { return Caps{FirewallEnabled: true} }

// HasDim reports whether the HTTP dataset exposes a dimension.
func (c Caps) HasDim(dim string) bool {
	if !c.Probed {
		return true
	}
	return c.HTTPFields["dimensions_"+dim]
}

// Capabilities probes the zone's dataset settings.
func (c *Client) Capabilities(ctx context.Context, zoneID string) (Caps, error) {
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:%s}){settings{httpRequestsAdaptiveGroups{enabled availableFields}firewallEventsAdaptiveGroups{enabled notOlderThan}}}}}`, quote(zoneID))
	body, _ := json.Marshal(map[string]string{"query": q})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return AllCaps(), err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return AllCaps(), err
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Settings struct {
						HTTP struct {
							Enabled         bool     `json:"enabled"`
							AvailableFields []string `json:"availableFields"`
						} `json:"httpRequestsAdaptiveGroups"`
						Firewall struct {
							Enabled      bool  `json:"enabled"`
							NotOlderThan int64 `json:"notOlderThan"` // seconds
						} `json:"firewallEventsAdaptiveGroups"`
					} `json:"settings"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return AllCaps(), fmt.Errorf("capabilities: decode: %w", err)
	}
	if len(out.Errors) > 0 {
		return AllCaps(), fmt.Errorf("capabilities: %s", out.Errors[0].Message)
	}
	if len(out.Data.Viewer.Zones) == 0 {
		return AllCaps(), ErrNoAccess
	}
	st := out.Data.Viewer.Zones[0].Settings
	caps := Caps{HTTPFields: map[string]bool{}, FirewallEnabled: st.Firewall.Enabled, Probed: true,
		FirewallMaxAge: time.Duration(st.Firewall.NotOlderThan) * time.Second}
	for _, f := range st.HTTP.AvailableFields {
		caps.HTTPFields[f] = true
	}
	return caps, nil
}

// Dimension for Cloudflare's own verified-bot classification.
const DimVerifiedBot = "verifiedBotCategory"

// Firewall dimension names accepted by FirewallTop.
const (
	FwDimIP      = "clientIP"
	FwDimASN     = "clientAsn"
	FwDimCountry = "clientCountryName"
	FwDimUA      = "userAgent"
)

// FirewallTop returns firewall-event counts of one rule grouped by one
// dimension — "how often did each blocked object try" (SPEC 7.4).
func (c *Client) FirewallTop(ctx context.Context, zoneID string, from, to time.Time, ruleID, dim string, limit int) ([]Face, error) {
	rows, err := c.zoneRows(ctx, zoneID, "firewallEventsAdaptiveGroups", "count dimensions{"+dim+"}", limit, true,
		Filter{FirewallRuleID: ruleID}.render(from, to))
	if err != nil {
		return nil, err
	}
	return faces(rows, dim), nil
}

// WorkerStats returns invocation count (requests, including subrequests)
// and CPU P50 in milliseconds for one Worker script in the window.
// The dataset has quantiles only; there is no CPU total — cost estimates
// must be derived and labelled as estimates.
func (c *Client) WorkerStats(ctx context.Context, accountID, script string, from, to time.Time) (requests int64, cpuP50ms float64, err error) {
	q := fmt.Sprintf(`{viewer{accounts(filter:{accountTag:%s}){workersInvocationsAdaptive(limit:100,filter:{%s}){sum{requests}quantiles{cpuTimeP50}}}}}`,
		quote(accountID), Filter{WorkerScript: script}.render(from, to))
	r, err := c.query(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	if len(r.Data.Viewer.Accounts) == 0 {
		return 0, 0, ErrNoAccess
	}
	// Usually a single group. If the API splits it, the request-weighted
	// mean of the P50s is an approximation, not a true quantile.
	var wsum float64
	for _, inv := range r.Data.Viewer.Accounts[0].Workers {
		requests += inv.Sum.Requests
		wsum += inv.Quantiles.CPUP50 * float64(inv.Sum.Requests)
	}
	if requests > 0 {
		cpuP50ms = wsum / float64(requests) / 1000.0
	}
	return requests, cpuP50ms, nil
}

// ---- calibration (SPEC 15, v1.0) ----

// Dashboard is one UTC day as the Cloudflare dashboard counts it
// (httpRequests1dGroups: not sampled, no Worker subrequests).
type Dashboard struct {
	Requests int64
	Cached   int64
	Edge5xx  int64
}

// DashboardDay returns the dashboard-grade totals of one UTC date.
func (c *Client) DashboardDay(ctx context.Context, zoneID string, date time.Time) (Dashboard, error) {
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:%s}){httpRequests1dGroups(limit:1,filter:{date:%s}){sum{requests cachedRequests responseStatusMap{edgeResponseStatus requests}}}}}}`,
		quote(zoneID), quote(date.UTC().Format("2006-01-02")))
	var out struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Days []struct {
						Sum struct {
							Requests  int64 `json:"requests"`
							Cached    int64 `json:"cachedRequests"`
							StatusMap []struct {
								Status   int   `json:"edgeResponseStatus"`
								Requests int64 `json:"requests"`
							} `json:"responseStatusMap"`
						} `json:"sum"`
					} `json:"httpRequests1dGroups"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := c.queryInto(ctx, q, &out); err != nil {
		return Dashboard{}, err
	}
	if len(out.Errors) > 0 {
		return Dashboard{}, fmt.Errorf("cloudflare API: %s", out.Errors[0].Message)
	}
	if len(out.Data.Viewer.Zones) == 0 {
		return Dashboard{}, ErrNoAccess
	}
	var d Dashboard
	for _, day := range out.Data.Viewer.Zones[0].Days {
		d.Requests += day.Sum.Requests
		d.Cached += day.Sum.Cached
		for _, s := range day.Sum.StatusMap {
			if s.Status >= 500 && s.Status < 600 {
				d.Edge5xx += s.Requests
			}
		}
	}
	return d, nil
}

// Sampling returns the adaptive count of a window and its average sample
// interval (1 = unsampled; 10 = one request in ten was kept).
func (c *Client) Sampling(ctx context.Context, zoneID string, from, to time.Time) (count int64, interval float64, err error) {
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:%s}){httpRequestsAdaptiveGroups(limit:1,filter:{%s}){count avg{sampleInterval}}}}}`,
		quote(zoneID), Filter{}.render(from, to))
	var out struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Rows []struct {
						Count int64 `json:"count"`
						Avg   struct {
							SampleInterval float64 `json:"sampleInterval"`
						} `json:"avg"`
					} `json:"httpRequestsAdaptiveGroups"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := c.queryInto(ctx, q, &out); err != nil {
		return 0, 0, err
	}
	if len(out.Errors) > 0 {
		return 0, 0, fmt.Errorf("cloudflare API: %s", out.Errors[0].Message)
	}
	if len(out.Data.Viewer.Zones) == 0 {
		return 0, 0, ErrNoAccess
	}
	for _, r := range out.Data.Viewer.Zones[0].Rows {
		count += r.Count
		interval = r.Avg.SampleInterval
	}
	return count, interval, nil
}

// Hourly returns adaptive counts per clock hour in [from, to) — the data
// behind the charts. Hours with no row are absent from the map.
func (c *Client) Hourly(ctx context.Context, zoneID string, from, to time.Time, f Filter) (map[time.Time]int64, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups", "count dimensions{datetimeHour}", 200, false, f.render(from, to))
	if err != nil {
		return nil, err
	}
	out := map[time.Time]int64{}
	for _, r := range rows {
		s, _ := r.Dimensions["datetimeHour"].(string)
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			continue
		}
		out[t.UTC()] += r.Count
	}
	return out, nil
}

// retryDelays are the waits before each retry of a read request.
var retryDelays = []time.Duration{time.Second, 3 * time.Second}

// doRetry sends a read-only request, retrying transport errors, 429 and
// 5xx responses. body is the request body to resend (nil for none). Never
// used for writes: a retried write could be applied twice.
func doRetry(ctx context.Context, hc *http.Client, req *http.Request, body []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		if attempt > 0 && body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		resp, err := hc.Do(req)
		retry := err != nil || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if !retry || attempt >= len(retryDelays) || ctx.Err() != nil {
			return resp, err
		}
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelays[attempt]):
		}
	}
}
