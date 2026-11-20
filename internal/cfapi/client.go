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
	// Where is a pre-rendered filter fragment appended as is (the rule
	// simulator's translated expression: "AND:[{…}]"). The caller owns
	// its quoting.
	Where string
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
	if f.Where != "" {
		parts = append(parts, f.Where)
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
		CPUP99 float64 `json:"cpuTimeP99"` // microseconds
		// Origin latency P95s, milliseconds (OriginStats only).
		OriginTTFBP95  float64 `json:"originResponseHeaderReceiveDurationMsP95"`
		OriginTotalP95 float64 `json:"originResponseDurationMsP95"`
		OriginTCPP95   float64 `json:"originTcpHandshakeDurationMsP95"`
		OriginTLSP95   float64 `json:"originTlsHandshakeDurationMsP95"`
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
	Cat   string `json:"cat,omitempty"`  // verified-bot category (client-IP lists only)
	Desc  string `json:"desc,omitempty"` // registered network name (DimASNNamed only)
}

// Dimension names accepted by Top.
const (
	DimUserAgent   = "userAgent"
	DimASN         = "clientAsn"
	DimPath        = "clientRequestPath"
	DimCacheStatus = "cacheStatus"
	DimClientIP    = "clientIP"
	// Client-IP groupings with more: one row per address (an address
	// belongs to one network and is one bot or not), Name the address,
	// ASN its network, Cat Cloudflare's verified-bot category ("" when
	// not a verified bot). Plans without a dimension reject its grouping.
	DimClientIPASN    = "clientIP clientAsn"
	DimClientIPBot    = "clientIP verifiedBotCategory"
	DimClientIPASNBot = "clientIP clientAsn verifiedBotCategory"
	// DimASNNamed groups by network with its registered name: ASN set,
	// Name "AS15169", Desc the registered name.
	DimASNNamed = "clientAsn clientASNDescription"
)

// Status dimensions: what the origin answered, and what the edge answered
// (the 52x family is generated by the edge when the origin cannot be
// reached — the origin answered nothing, so its status is 0).
const (
	DimOriginStatus = "originResponseStatus"
	DimEdgeStatus   = "edgeResponseStatus"
)

// OriginAnswered selects requests the origin actually answered
// (originResponseStatus > 0): cache hits, edge blocks and 52x — the
// origin never answered those — are left out. Origin latency quantiles
// must be read over this set only; cache hits would pull them to 0.
func OriginAnswered() Filter { return Filter{OriginStatusFrom: 1} }

// OriginUnreachable selects the edge's "could not reach the origin"
// answers: 520–526 (unknown error, down, timeout, unreachable, response
// timeout, TLS handshake/certificate) and 530 (origin DNS/tunnel).
func OriginUnreachable() Filter { return Filter{EdgeStatusFrom: 520, EdgeStatusTo: 531} }

// EdgeBlocked selects requests stopped at the edge: 403 and never sent
// to the origin (originResponseStatus 0), so a 403 the origin itself
// returned is not counted.
func EdgeBlocked() Filter { return Filter{EdgeStatus: 403, OriginStatusTo: 1} }

// Top returns the Top-N groups of one dimension, ordered by count.
func (c *Client) Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f Filter) ([]Face, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups", "count dimensions{"+dim+"}", limit, true, f.render(from, to))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(dim, DimClientIP+" ") {
		out := make([]Face, 0, len(rows))
		for _, r := range rows {
			f := Face{Name: fmt.Sprint(r.Dimensions[DimClientIP]), Count: r.Count}
			f.ASN, _ = asnOf(r.Dimensions[DimASN])
			f.Cat, _ = r.Dimensions[DimVerifiedBot].(string)
			out = append(out, f)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		return out, nil
	}
	if dim == DimASNNamed {
		out := make([]Face, 0, len(rows))
		for _, r := range rows {
			f := Face{Count: r.Count, Name: fmt.Sprint(r.Dimensions[DimASN])}
			if n, ok := asnOf(r.Dimensions[DimASN]); ok {
				f.ASN, f.Name = n, fmt.Sprintf("AS%d", n)
			}
			f.Desc, _ = r.Dimensions["clientASNDescription"].(string)
			out = append(out, f)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		return out, nil
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
	// FirewallFields is the firewall dataset's availableFields (empty:
	// not reported, everything is assumed available).
	FirewallFields map[string]bool
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

// ClientIPDim is the richest client-IP grouping the plan supports:
// with the address's network and verified-bot category where available.
func (c Caps) ClientIPDim() string {
	asn, bot := c.HasDim(DimASN), c.HasDim(DimVerifiedBot)
	switch {
	case asn && bot:
		return DimClientIPASNBot
	case asn:
		return DimClientIPASN
	case bot:
		return DimClientIPBot
	}
	return DimClientIP
}

// SplitBots separates Cloudflare-verified bots (Cat set) from the other
// addresses of a client-IP list, keeping at most n of the others.
func SplitBots(fs []Face, n int) (others, bots []Face) {
	for _, f := range fs {
		switch {
		case f.Cat != "":
			bots = append(bots, f)
		case len(others) < n:
			others = append(others, f)
		}
	}
	return others, bots
}

// HasFirewallDim reports whether the firewall-events dataset is enabled
// and exposes a dimension (assumed when the probe did not list fields).
func (c Caps) HasFirewallDim(dim string) bool {
	if !c.Probed {
		return true
	}
	if !c.FirewallEnabled {
		return false
	}
	if len(c.FirewallFields) == 0 {
		return true
	}
	return c.FirewallFields["dimensions_"+dim]
}

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
	if caps.FirewallEnabled {
		// Best effort, in its own query: a failure here must not cost the
		// watch its main probe. Without the list every field is assumed.
		caps.FirewallFields = c.firewallFields(ctx, zoneID)
	}
	return caps, nil
}

// firewallFields reads the firewall dataset's availableFields (nil when
// the read fails) — what the rule simulator may filter firewall events on.
func (c *Client) firewallFields(ctx context.Context, zoneID string) map[string]bool {
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:%s}){settings{firewallEventsAdaptiveGroups{availableFields}}}}}`, quote(zoneID))
	var out struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Settings struct {
						Firewall struct {
							AvailableFields []string `json:"availableFields"`
						} `json:"firewallEventsAdaptiveGroups"`
					} `json:"settings"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := c.queryInto(ctx, q, &out); err != nil || len(out.Errors) > 0 || len(out.Data.Viewer.Zones) == 0 {
		return nil
	}
	fs := out.Data.Viewer.Zones[0].Settings.Firewall.AvailableFields
	if len(fs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f] = true
	}
	return m
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

// FirewallGroups returns firewall-event counts grouped by one or more
// dimensions (space-separated, e.g. "action" or "action ruleId") under a
// filter — the rule simulator's "already handled by existing rules".
// Not available on every plan: an error means "data unavailable".
func (c *Client) FirewallGroups(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f Filter) ([]Face, error) {
	rows, err := c.zoneRows(ctx, zoneID, "firewallEventsAdaptiveGroups", "count dimensions{"+dim+"}", limit, true, f.render(from, to))
	if err != nil {
		return nil, err
	}
	return faces(rows, strings.Fields(dim)...), nil
}

// WorkerStat is one Worker script's window: invocations (including
// subrequests) and CPU time quantiles in milliseconds.
type WorkerStat struct {
	Requests int64
	CPUP50ms float64
	CPUP99ms float64
}

// WorkerStats returns invocation count and the CPU P50 / P99 for one
// Worker script in the window — one query, both quantiles. The P99 is
// what tells "the typical call got more expensive" from "the cheap calls
// left and the median moved" (a mix change).
// The dataset has quantiles only; there is no CPU total — cost estimates
// must be derived and labelled as estimates.
func (c *Client) WorkerStats(ctx context.Context, accountID, script string, from, to time.Time) (WorkerStat, error) {
	var st WorkerStat
	q := fmt.Sprintf(`{viewer{accounts(filter:{accountTag:%s}){workersInvocationsAdaptive(limit:100,filter:{%s}){sum{requests}quantiles{cpuTimeP50 cpuTimeP99}}}}}`,
		quote(accountID), Filter{WorkerScript: script}.render(from, to))
	r, err := c.query(ctx, q)
	if err != nil {
		return st, err
	}
	if len(r.Data.Viewer.Accounts) == 0 {
		return st, ErrNoAccess
	}
	// Usually a single group. If the API splits it, the request-weighted
	// mean of the quantiles is an approximation, not a true quantile.
	var w50, w99 float64
	for _, inv := range r.Data.Viewer.Accounts[0].Workers {
		st.Requests += inv.Sum.Requests
		w50 += inv.Quantiles.CPUP50 * float64(inv.Sum.Requests)
		w99 += inv.Quantiles.CPUP99 * float64(inv.Sum.Requests)
	}
	if st.Requests > 0 {
		st.CPUP50ms = w50 / float64(st.Requests) / 1000.0
		st.CPUP99ms = w99 / float64(st.Requests) / 1000.0
	}
	return st, nil
}

// MinuteCount is one minute of a per-minute breakdown.
type MinuteCount struct {
	At time.Time
	Face
}

// Minutes returns per-minute counts, newest first, of the firewall-events
// dataset (firewall true) or the HTTP requests dataset, optionally split
// by one more dimension (dim, "" for none). It is the live check behind
// "is this block catching anything right now" — the minute grain also
// says when the last attempt was.
func (c *Client) Minutes(ctx context.Context, zoneID string, firewall bool, from, to time.Time, dim string, f Filter, limit int) ([]MinuteCount, error) {
	dataset := "httpRequestsAdaptiveGroups"
	if firewall {
		dataset = "firewallEventsAdaptiveGroups"
	}
	dims := "datetimeMinute"
	if dim != "" {
		dims += " " + dim
	}
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:%s}){%s(limit:%d,orderBy:[datetimeMinute_DESC],filter:{%s}){count dimensions{%s}}}}}`,
		quote(zoneID), dataset, limit, f.render(from, to), dims)
	r, err := c.query(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(r.Data.Viewer.Zones) == 0 {
		return nil, ErrNoAccess
	}
	rows := r.Data.Viewer.Zones[0].HTTP
	if firewall {
		rows = r.Data.Viewer.Zones[0].Firewall
	}
	out := make([]MinuteCount, 0, len(rows))
	for _, rw := range rows {
		m := MinuteCount{Face: Face{Count: rw.Count}}
		if s, ok := rw.Dimensions["datetimeMinute"].(string); ok {
			m.At, _ = time.Parse(time.RFC3339, s)
		}
		if dim != "" {
			v := rw.Dimensions[dim]
			if dim == DimASN || dim == FwDimASN {
				m.ASN, _ = asnOf(v)
			}
			m.Name = fmt.Sprint(v)
		}
		out = append(out, m)
	}
	return out, nil
}

// OriginStats is the origin's side of a window, read over the requests
// it actually answered (see OriginAnswered). Latencies are P95s in ms:
// TTFB is the wait for the response headers (the application computing),
// Total the whole response (TTFB plus transfer), TCP/TLS the connection
// set-up (often 0: connections are reused).
type OriginStats struct {
	Requests int64
	TTFBP95  float64
	TotalP95 float64
	TCPP95   float64
	TLSP95   float64
}

// OriginStats reads the origin's answered-request count and latency P95s
// for the window. Adaptive data is sampled: fit for trends and alerts,
// not for SLA accounting.
func (c *Client) OriginStats(ctx context.Context, zoneID string, from, to time.Time) (OriginStats, error) {
	rows, err := c.zoneRows(ctx, zoneID, "httpRequestsAdaptiveGroups",
		"count quantiles{originResponseHeaderReceiveDurationMsP95 originResponseDurationMsP95 originTcpHandshakeDurationMsP95 originTlsHandshakeDurationMsP95}",
		1, false, OriginAnswered().render(from, to))
	if err != nil {
		return OriginStats{}, err
	}
	var s OriginStats
	for _, r := range rows { // one group: no dimensions
		s.Requests += r.Count
		s.TTFBP95, s.TotalP95 = r.Quantiles.OriginTTFBP95, r.Quantiles.OriginTotalP95
		s.TCPP95, s.TLSP95 = r.Quantiles.OriginTCPP95, r.Quantiles.OriginTLSP95
	}
	return s, nil
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
