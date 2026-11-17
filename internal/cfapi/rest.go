package cfapi

// REST client for the few non-GraphQL endpoints FlareHound needs: zone
// plan, DNS origin IPs and Cloudflare's own ranges (guard rails), plus —
// only with the separate write token (SPEC 13.1) — the custom-rule
// ruleset, the account IP list and IP Access Rules that one-click
// blocking maintains. Every call goes to api.cloudflare.com.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// DefaultREST is the REST API base.
const DefaultREST = "https://api.cloudflare.com/client/v4"

type REST struct {
	token string
	base  string
	http  *http.Client
}

func NewREST(token string) *REST {
	return &REST{token: token, base: DefaultREST, http: &http.Client{Timeout: 60 * time.Second}}
}

// WithBase overrides the API base (tests only).
func (c *REST) WithBase(u string) *REST { c.base = u; return c }

// APIError is a Cloudflare REST error; Status is the HTTP status.
type APIError struct {
	Status  int
	Code    int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloudflare API: HTTP %d: %d %s", e.Status, e.Code, e.Message)
}

// IsNotFound reports whether err is a 404 from the API.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiMsg        `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
		Cursors    struct {
			After string `json:"after"`
		} `json:"cursors"`
	} `json:"result_info"`
}

type apiMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *REST) do(ctx context.Context, method, path string, body, out any) (*envelope, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, fmt.Errorf("cloudflare API: %s %s: %v", method, path, ue.Err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &APIError{Status: resp.StatusCode, Message: truncate(raw, 200)}
	}
	if resp.StatusCode/100 != 2 || !env.Success {
		e := &APIError{Status: resp.StatusCode}
		if len(env.Errors) > 0 {
			e.Code, e.Message = env.Errors[0].Code, env.Errors[0].Message
		}
		return nil, e
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("cloudflare API: decode %s: %w", path, err)
		}
	}
	return &env, nil
}

// ---- read side (guard rails / capability) ----

// ZonePlan returns the zone's plan id: "free", "pro", "business",
// "enterprise" (Cloudflare's plan.legacy_id).
func (c *REST) ZonePlan(ctx context.Context, zoneID string) (string, error) {
	var z struct {
		Plan struct {
			LegacyID string `json:"legacy_id"`
		} `json:"plan"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID), nil, &z); err != nil {
		return "", err
	}
	return z.Plan.LegacyID, nil
}

// OriginIPs returns every address in the zone's A/AAAA records — the
// origin IPs that must never be blocked.
func (c *REST) OriginIPs(ctx context.Context, zoneID string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, typ := range []string{"A", "AAAA"} {
		for page := 1; ; page++ {
			var recs []struct {
				Content string `json:"content"`
			}
			env, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/dns_records?type=%s&per_page=1000&page=%d", url.PathEscape(zoneID), typ, page), nil, &recs)
			if err != nil {
				return nil, err
			}
			for _, r := range recs {
				if a, err := netip.ParseAddr(r.Content); err == nil {
					out = append(out, a)
				}
			}
			if env.ResultInfo.TotalPages <= page {
				break
			}
		}
	}
	return out, nil
}

// CloudflareRanges returns Cloudflare's published IP ranges (public
// endpoint, no token needed).
func (c *REST) CloudflareRanges(ctx context.Context) ([]netip.Prefix, error) {
	var r struct {
		V4 []string `json:"ipv4_cidrs"`
		V6 []string `json:"ipv6_cidrs"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/ips", nil, &r); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, s := range append(r.V4, r.V6...) {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// ---- rulesets (custom rules phase) ----

// PhaseCustom is the WAF custom rules phase.
const PhaseCustom = "http_request_firewall_custom"

type Rule struct {
	ID          string `json:"id,omitempty"`
	Ref         string `json:"ref,omitempty"`
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type Ruleset struct {
	ID    string `json:"id"`
	Rules []Rule `json:"rules"`
}

// Entrypoint returns the zone's custom-rules entrypoint ruleset; found is
// false when the zone has none yet.
func (c *REST) Entrypoint(ctx context.Context, zoneID string) (rs Ruleset, found bool, err error) {
	_, err = c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/rulesets/phases/"+PhaseCustom+"/entrypoint", nil, &rs)
	if IsNotFound(err) {
		return Ruleset{}, false, nil
	}
	return rs, err == nil, err
}

// CreateEntrypoint creates the entrypoint with one rule. Callers must only
// use it when Entrypoint reported none: on an existing entrypoint this
// PUT would replace the user's rules.
func (c *REST) CreateEntrypoint(ctx context.Context, zoneID string, r Rule) (Ruleset, error) {
	var rs Ruleset
	_, err := c.do(ctx, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/rulesets/phases/"+PhaseCustom+"/entrypoint",
		map[string]any{"rules": []Rule{r}}, &rs)
	return rs, err
}

// AddRule appends a rule to the ruleset (after the user's rules).
func (c *REST) AddRule(ctx context.Context, zoneID, rulesetID string, r Rule) (Ruleset, error) {
	var rs Ruleset
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/rulesets/%s/rules", url.PathEscape(zoneID), url.PathEscape(rulesetID)), r, &rs)
	return rs, err
}

// UpdateRule replaces one rule in place.
func (c *REST) UpdateRule(ctx context.Context, zoneID, rulesetID string, r Rule) (Ruleset, error) {
	var rs Ruleset
	id := r.ID
	r.ID = ""
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", url.PathEscape(zoneID), url.PathEscape(rulesetID), url.PathEscape(id)), r, &rs)
	return rs, err
}

// DeleteRule removes one rule.
func (c *REST) DeleteRule(ctx context.Context, zoneID, rulesetID, ruleID string) (Ruleset, error) {
	var rs Ruleset
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", url.PathEscape(zoneID), url.PathEscape(rulesetID), url.PathEscape(ruleID)), nil, &rs)
	return rs, err
}

// ---- account IP lists ----

type List struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
}

type ListItem struct {
	ID      string `json:"id,omitempty"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

func (c *REST) Lists(ctx context.Context, accountID string) ([]List, error) {
	var ls []List
	_, err := c.do(ctx, http.MethodGet, "/accounts/"+url.PathEscape(accountID)+"/rules/lists", nil, &ls)
	return ls, err
}

func (c *REST) CreateList(ctx context.Context, accountID, name, description string) (List, error) {
	var l List
	_, err := c.do(ctx, http.MethodPost, "/accounts/"+url.PathEscape(accountID)+"/rules/lists",
		map[string]string{"name": name, "kind": "ip", "description": description}, &l)
	return l, err
}

// ListItems returns every item of a list (cursor-paginated).
func (c *REST) ListItems(ctx context.Context, accountID, listID string) ([]ListItem, error) {
	var all []ListItem
	cursor := ""
	for {
		p := fmt.Sprintf("/accounts/%s/rules/lists/%s/items?per_page=500", url.PathEscape(accountID), url.PathEscape(listID))
		if cursor != "" {
			p += "&cursor=" + url.QueryEscape(cursor)
		}
		var items []ListItem
		env, err := c.do(ctx, http.MethodGet, p, nil, &items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		cursor = env.ResultInfo.Cursors.After
		if cursor == "" {
			return all, nil
		}
	}
}

// AddListItems appends items and waits for the async bulk operation.
func (c *REST) AddListItems(ctx context.Context, accountID, listID string, items []ListItem) error {
	var op struct {
		OperationID string `json:"operation_id"`
	}
	if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/accounts/%s/rules/lists/%s/items", url.PathEscape(accountID), url.PathEscape(listID)), items, &op); err != nil {
		return err
	}
	return c.waitBulk(ctx, accountID, op.OperationID)
}

// DeleteListItems removes items by item ID and waits for completion.
func (c *REST) DeleteListItems(ctx context.Context, accountID, listID string, ids []string) error {
	type idRef struct {
		ID string `json:"id"`
	}
	refs := make([]idRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, idRef{id})
	}
	var op struct {
		OperationID string `json:"operation_id"`
	}
	if _, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/accounts/%s/rules/lists/%s/items", url.PathEscape(accountID), url.PathEscape(listID)),
		map[string]any{"items": refs}, &op); err != nil {
		return err
	}
	return c.waitBulk(ctx, accountID, op.OperationID)
}

func (c *REST) waitBulk(ctx context.Context, accountID, opID string) error {
	if opID == "" {
		return nil
	}
	for i := 0; i < 60; i++ {
		var st struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/accounts/%s/rules/lists/bulk_operations/%s", url.PathEscape(accountID), url.PathEscape(opID)), nil, &st); err != nil {
			return err
		}
		switch st.Status {
		case "completed":
			return nil
		case "failed":
			return fmt.Errorf("list operation failed: %s", st.Error)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("list operation did not complete within 30s")
}

// ---- IP Access Rules (fallback when the custom-rule quota is full) ----

type AccessRule struct {
	ID            string `json:"id"`
	Mode          string `json:"mode"` // block | managed_challenge
	Notes         string `json:"notes"`
	Configuration struct {
		Target string `json:"target"` // ip | ip_range | asn
		Value  string `json:"value"`
	} `json:"configuration"`
}

func (c *REST) AccessRules(ctx context.Context, zoneID, notesContains string) ([]AccessRule, error) {
	var all []AccessRule
	for page := 1; ; page++ {
		var rs []AccessRule
		env, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/firewall/access_rules/rules?notes=%s&per_page=500&page=%d",
			url.PathEscape(zoneID), url.QueryEscape(notesContains), page), nil, &rs)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if strings.Contains(r.Notes, notesContains) {
				all = append(all, r)
			}
		}
		if env.ResultInfo.TotalPages <= page {
			return all, nil
		}
	}
}

func (c *REST) CreateAccessRule(ctx context.Context, zoneID, mode, target, value, notes string) (AccessRule, error) {
	var r AccessRule
	_, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/firewall/access_rules/rules", map[string]any{
		"mode": mode, "notes": notes, "configuration": map[string]string{"target": target, "value": value},
	}, &r)
	return r, err
}

func (c *REST) DeleteAccessRule(ctx context.Context, zoneID, id string) error {
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/firewall/access_rules/rules/%s", url.PathEscape(zoneID), url.PathEscape(id)), nil, nil)
	return err
}
