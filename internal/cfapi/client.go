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
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const endpoint = "https://api.cloudflare.com/client/v4/graphql"

type Client struct {
	token string
	http  *http.Client
}

func New(token string) *Client {
	return &Client{token: token, http: &http.Client{Timeout: 60 * time.Second}}
}

type gqlResponse struct {
	Data struct {
		Viewer struct {
			Zones []struct {
				Groups []group `json:"httpRequestsAdaptiveGroups"`
			} `json:"zones"`
			Accounts []struct {
				Invocations []invocation `json:"workersInvocationsAdaptive"`
			} `json:"accounts"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type group struct {
	Count      int64 `json:"count"`
	Dimensions struct {
		UserAgent string `json:"userAgent"`
		ClientASN int    `json:"clientAsn"`
		Path      string `json:"clientRequestPath"`
	} `json:"dimensions"`
}

type invocation struct {
	Sum struct {
		Requests int64 `json:"requests"`
	} `json:"sum"`
	Quantiles struct {
		CPUP50 float64 `json:"cpuTimeP50"` // microseconds
	} `json:"quantiles"`
}

func (c *Client) query(ctx context.Context, q string) (*gqlResponse, error) {
	body, _ := json.Marshal(map[string]string{"query": q})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
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
	raw, err := io.ReadAll(resp.Body)
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

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func (c *Client) zoneCount(ctx context.Context, zoneID string, from, to time.Time, extraFilter string) (int64, error) {
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:"%s"}){httpRequestsAdaptiveGroups(limit:1,filter:{datetime_geq:"%s",datetime_lt:"%s"%s}){count}}}}`,
		zoneID, ts(from), ts(to), extraFilter)
	r, err := c.query(ctx, q)
	if err != nil {
		return 0, err
	}
	if len(r.Data.Viewer.Zones) == 0 || len(r.Data.Viewer.Zones[0].Groups) == 0 {
		return 0, nil
	}
	return r.Data.Viewer.Zones[0].Groups[0].Count, nil
}

// TotalRequests returns all adaptive-counted requests in the window.
func (c *Client) TotalRequests(ctx context.Context, zoneID string, from, to time.Time) (int64, error) {
	return c.zoneCount(ctx, zoneID, from, to, "")
}

// DynamicRequests returns uncached (origin/Worker-rendered) responses.
func (c *Client) DynamicRequests(ctx context.Context, zoneID string, from, to time.Time) (int64, error) {
	return c.zoneCount(ctx, zoneID, from, to, `,cacheStatus:"dynamic"`)
}

// Origin5xx returns responses whose origin status was 500-599.
func (c *Client) Origin5xx(ctx context.Context, zoneID string, from, to time.Time) (int64, error) {
	return c.zoneCount(ctx, zoneID, from, to, `,originResponseStatus_geq:500,originResponseStatus_lt:600`)
}

// Face is one row of a Top-N breakdown (user agent or ASN).
type Face struct {
	Name  string
	Count int64
}

func (c *Client) topFaces(ctx context.Context, zoneID string, from, to time.Time, limit int, dimension string) ([]Face, error) {
	q := fmt.Sprintf(`{viewer{zones(filter:{zoneTag:"%s"}){httpRequestsAdaptiveGroups(limit:%d,orderBy:[count_DESC],filter:{datetime_geq:"%s",datetime_lt:"%s"}){count dimensions{%s}}}}}`,
		zoneID, limit, ts(from), ts(to), dimension)
	r, err := c.query(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(r.Data.Viewer.Zones) == 0 {
		return nil, nil
	}
	var out []Face
	for _, g := range r.Data.Viewer.Zones[0].Groups {
		name := g.Dimensions.UserAgent
		if dimension == "clientAsn" {
			name = fmt.Sprintf("AS%d", g.Dimensions.ClientASN)
		}
		out = append(out, Face{Name: name, Count: g.Count})
	}
	return out, nil
}

// TopUserAgents returns the Top-N user agents by request count.
func (c *Client) TopUserAgents(ctx context.Context, zoneID string, from, to time.Time, limit int) ([]Face, error) {
	return c.topFaces(ctx, zoneID, from, to, limit, "userAgent")
}

// TopASNs returns the Top-N client ASNs by request count.
func (c *Client) TopASNs(ctx context.Context, zoneID string, from, to time.Time, limit int) ([]Face, error) {
	return c.topFaces(ctx, zoneID, from, to, limit, "clientAsn")
}

// WorkerStats returns invocation count and CPU P50 (milliseconds) for one
// Worker script in the window. The dataset has quantiles only; there is no
// CPU total — cost estimates must be derived and labelled as estimates.
func (c *Client) WorkerStats(ctx context.Context, accountID, script string, from, to time.Time) (requests int64, cpuP50ms float64, err error) {
	q := fmt.Sprintf(`{viewer{accounts(filter:{accountTag:"%s"}){workersInvocationsAdaptive(limit:10,filter:{datetime_geq:"%s",datetime_lt:"%s",scriptName:"%s"}){sum{requests}quantiles{cpuTimeP50}}}}}`,
		accountID, ts(from), ts(to), script)
	r, err := c.query(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	if len(r.Data.Viewer.Accounts) == 0 || len(r.Data.Viewer.Accounts[0].Invocations) == 0 {
		return 0, 0, nil
	}
	inv := r.Data.Viewer.Accounts[0].Invocations[0]
	return inv.Sum.Requests, inv.Quantiles.CPUP50 / 1000.0, nil
}
