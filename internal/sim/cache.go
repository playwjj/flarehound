package sim

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache keeps simulations for CacheTTL: the same expression simulated
// again (the review page, then apply) does not spend the query budget
// twice. A nil *Cache runs every simulation.
type Cache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

type cacheEntry struct {
	at time.Time
	r  *Report
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{m: map[string]cacheEntry{}} }

func key(in Input) string {
	ahead := "?"
	if in.AheadKnown {
		ids := make([]string, len(in.Ahead))
		for i, r := range in.Ahead {
			ids[i] = r.ID
		}
		ahead = strings.Join(ids, ",")
	}
	return strings.Join([]string{in.ZoneID, strings.TrimSpace(in.Expr), in.Action,
		in.From.UTC().Format(time.RFC3339), in.To.UTC().Format(time.RFC3339), strconv.Itoa(in.Before), ahead}, "\x00")
}

// Run returns a cached report younger than CacheTTL, or simulates.
func (c *Cache) Run(ctx context.Context, api API, in Input) (*Report, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.From.IsZero() || in.To.IsZero() {
		in.From, in.To = Window(in.Now, in.Days)
	}
	if c == nil {
		return Run(ctx, api, in)
	}
	k := key(in)
	c.mu.Lock()
	for kk, e := range c.m {
		if in.Now.Sub(e.at) > CacheTTL {
			delete(c.m, kk)
		}
	}
	if e, ok := c.m[k]; ok {
		c.mu.Unlock()
		cp := *e.r
		cp.Cached = true
		return &cp, nil
	}
	c.mu.Unlock()
	r, err := Run(ctx, api, in)
	if err != nil {
		return r, err
	}
	if len(r.Errors) == 0 {
		c.mu.Lock()
		c.m[k] = cacheEntry{at: in.Now, r: r}
		c.mu.Unlock()
	}
	return r, nil
}

// Decode reads a stored snapshot.
func Decode(raw []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
