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
	PathLike          string // SQL-like pattern, % wildcard
	UserAgent         string // exact
	ASN               int    // exact
	WorkerScript      string // workers dataset only
	FirewallAction    string // firewall dataset only
	FirewallNotAction string // firewall dataset only
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
	if f.PathLike != "" {
		parts = append(parts, "clientRequestPath_like:"+quote(f.PathLike))
	}
	if f.UserAgent != "" {
		parts = append(parts, "userAgent:"+quote(f.UserAgent))
	}
	if f.ASN > 0 {
		parts = append(parts, fmt.Sprintf("clientAsn:%d", f.ASN))
	}
	if f.WorkerScript != "" {
		parts = append(parts, "scriptName:"+quote(f.WorkerScript))
	}
	if f.FirewallAction != "" {
		parts = append(parts, "action:"+quote(f.FirewallAction))
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
	body, _ := json.Marshal(map[string]string{"query": q})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare API: HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	var out gqlResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("cloudflare API: decode: %w", err)
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("cloudflare API: %s", out.Errors[0].Message)
	}
	return &out, nil
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

func faces(rows []row, dims ...string) []Face {
	out := make([]Face, 0, len(rows))
	for _, r := range rows {
		var names []string
		face := Face{Count: r.Count}
		for _, d := range dims {
			v := r.Dimensions[d]
			if d == DimASN {
				if n, ok := v.(float64); ok {
					face.ASN = int(n)
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
