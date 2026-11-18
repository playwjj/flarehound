package console

// IP board: which client addresses keep hitting the zone. The last hour
// is queried live (like the live tiles); the last 24 hours are summed
// from the archive, where the watch keeps each hour's top client IPs.
// Ranking by single address already plays down big crawlers (they spread
// over thousands of addresses) and brings up the concentrated sources a
// /32 block can stop. Addresses in a network the user marked known are
// folded away; crawler networks are labelled, never folded (AS8075 is
// Bingbot and Azure alike).

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

const (
	ipSpanHour = "1h"
	ipSpanDay  = "24h"
	ipLimit    = 50 // rows queried live (the archive keeps the same)
	ipShown    = 50 // rows shown on the board
	ipDayHours = 24
	ipLiveTTL  = time.Minute
	ipErrTTL   = 10 * time.Second
)

// IPRow is one address — or one IPv6 /64, whose addresses are summed.
type IPRow struct {
	Name     string // address, or "2001:db8:1:2::/64"
	Members  int    // addresses summed into a /64 (0: a single address)
	ASN      int    // 0: unknown (plan without ASN, or not reported)
	Crawler  string // crawler that crawls from this network, if any
	Known    bool   // the network is in the user's known faces
	Listed   bool   // inside an active FlareHound IP block
	Count    int64
	Share    float64 // percent of the window's requests
	Blocked  int64   // of Count, stopped at the edge (from the blocked top list)
	Hours    int     // archived hours this row was in the top list (24 h only)
	Strip    []bool  // per hour, oldest first (24 h only)
	Drill    bool    // can be drilled into (single addresses)
	BlockPct float64
}

// IPBoard is the board for one span.
type IPBoard struct {
	Span      string
	From, To  time.Time
	Total     int64   // the window's requests (hours with IP data only, for 24 h)
	Rows      []IPRow // unknown networks, ranked
	Known     []IPRow // folded: networks the user marked known
	KnownSum  int64
	Hours     int       // archived hours with IP data in the window (24 h)
	Since     time.Time // oldest archived hour with IP data (zero: none yet)
	SortHours bool      // 24 h ranked by persistence (else by requests)
	Err       string
	At        time.Time
}

type ipEntry struct {
	mu sync.Mutex
	b  *IPBoard
}

// ipKey groups an address: IPv6 by /64 (one host's usual allocation,
// which rotating clients move around in), IPv4 as is.
func ipKey(s string) (key string, v6 bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s, false
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String(), false
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String(), false
	}
	return p.String(), true
}

type ipAgg struct {
	row     IPRow
	members map[string]bool
}

// ipAggregator sums top lists (one per hour, or the live one) by key.
type ipAggregator struct {
	by    map[string]*ipAgg
	hours int // slots in the strip (0: no strip)
}

func newIPAggregator(hours int) *ipAggregator {
	return &ipAggregator{by: map[string]*ipAgg{}, hours: hours}
}

func (g *ipAggregator) get(name string) *ipAgg {
	k, v6 := ipKey(name)
	a := g.by[k]
	if a == nil {
		a = &ipAgg{row: IPRow{Name: k}}
		if v6 {
			a.members = map[string]bool{}
		}
		if g.hours > 0 {
			a.row.Strip = make([]bool, g.hours)
		}
		g.by[k] = a
	}
	if a.members != nil {
		a.members[name] = true
	}
	return a
}

// add sums one top list; slot is the hour's strip index (-1: none).
func (g *ipAggregator) add(top []cfapi.Face, slot int) {
	seen := map[string]bool{}
	for _, f := range top {
		a := g.get(f.Name)
		a.row.Count += f.Count
		if a.row.ASN == 0 {
			a.row.ASN = f.ASN
		}
		if slot >= 0 && !seen[a.row.Name] {
			seen[a.row.Name] = true
			a.row.Hours++
			a.row.Strip[slot] = true
		}
	}
}

// addBlocked sums one top list of edge-stopped requests into rows that
// exist (an address only blocked, never in the top of all requests, is
// not on the board: its requests are handled already).
func (g *ipAggregator) addBlocked(top []cfapi.Face) {
	for _, f := range top {
		k, _ := ipKey(f.Name)
		if a := g.by[k]; a != nil {
			a.row.Blocked += f.Count
		}
	}
}

// ipBlocks are the active FlareHound IP blocks of a zone.
func ipBlocks(evs []store.BlockEvent) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range evs {
		if e.Type != "ip" {
			continue
		}
		if a, err := netip.ParseAddr(e.Value); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else if p, err := netip.ParsePrefix(e.Value); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func listed(name string, blocks []netip.Prefix) bool {
	var p netip.Prefix
	if a, err := netip.ParseAddr(name); err == nil {
		p = netip.PrefixFrom(a, a.BitLen())
	} else if q, err := netip.ParsePrefix(name); err == nil {
		p = q
	} else {
		return false
	}
	for _, b := range blocks {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// finish turns the sums into the board's rows.
func (g *ipAggregator) finish(b *IPBoard, cfg *config.Config, blocks []netip.Prefix) {
	rows := make([]IPRow, 0, len(g.by))
	for _, a := range g.by {
		r := a.row
		if a.members != nil {
			r.Members = len(a.members)
		}
		if b.Total > 0 {
			r.Share = float64(r.Count) / float64(b.Total) * 100
		}
		if r.Count > 0 {
			r.BlockPct = min(100, float64(r.Blocked)/float64(r.Count)*100)
		}
		if r.ASN > 0 {
			r.Crawler, _ = analyze.CrawlerNetwork(r.ASN)
			r.Known = IsKnown(cfg, DimASN, "AS"+strconv.Itoa(r.ASN))
		}
		r.Listed = listed(r.Name, blocks)
		r.Drill = a.members == nil && !strings.Contains(r.Name, "/")
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if b.SortHours && rows[i].Hours != rows[j].Hours {
			return rows[i].Hours > rows[j].Hours
		}
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Name < rows[j].Name
	})
	for _, r := range rows {
		if r.Known {
			b.Known = append(b.Known, r)
			b.KnownSum += r.Count
		} else if len(b.Rows) < ipShown {
			b.Rows = append(b.Rows, r)
		}
	}
}

// buildIPDay sums the archive's last 24 hours (ending with the newest
// archived hour).
func buildIPDay(arch Archive, cfg *config.Config, z config.Zone, byCount bool) (*IPBoard, error) {
	b := &IPBoard{Span: ipSpanDay, SortHours: !byCount}
	latest, ok, err := arch.LatestHour(z.ZoneID)
	if err != nil || !ok {
		return b, err
	}
	b.To = latest.To
	b.From = latest.To.Add(-ipDayHours * time.Hour)
	hs, err := arch.HourSnapshots(z.ZoneID, b.From, b.To)
	if err != nil {
		return b, err
	}
	g := newIPAggregator(ipDayHours)
	for _, h := range hs {
		if h.TopIPs == nil { // before v1.14, or the query failed
			continue
		}
		slot := int(h.From.Sub(b.From) / time.Hour)
		if slot < 0 || slot >= ipDayHours {
			continue
		}
		if b.Since.IsZero() {
			b.Since = h.From
		}
		b.Hours++
		b.Total += h.Total
		g.add(h.TopIPs, slot)
		g.addBlocked(h.BlockedIPs)
	}
	evs, err := arch.ActiveBlocks(z.ZoneID)
	if err != nil {
		return b, err
	}
	g.finish(b, cfg, ipBlocks(evs))
	return b, nil
}

// buildIPHour queries the live hour: total, top IPs (with their network
// where the plan has it) and top IPs stopped at the edge, in parallel.
func buildIPHour(ctx context.Context, an Analytics, cfg *config.Config, z config.Zone, from, to time.Time, hasASN bool, blocks []netip.Prefix) (*IPBoard, error) {
	b := &IPBoard{Span: ipSpanHour, From: from, To: to}
	dim := cfapi.DimClientIP
	if hasASN {
		dim = cfapi.DimClientIPASN
	}
	var (
		wg           sync.WaitGroup
		top, blocked []cfapi.Face
		errs         = make([]error, 3)
	)
	run := func(i int, fn func() error) {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = fn() }()
	}
	run(0, func() (err error) { b.Total, err = an.Count(ctx, z.ZoneID, from, to, cfapi.Filter{}); return })
	run(1, func() (err error) { top, err = an.Top(ctx, z.ZoneID, from, to, dim, ipLimit, cfapi.Filter{}); return })
	run(2, func() (err error) {
		blocked, err = an.Top(ctx, z.ZoneID, from, to, cfapi.DimClientIP, ipLimit, cfapi.EdgeBlocked())
		return
	})
	wg.Wait()
	for _, err := range errs[:2] { // the blocked share is optional
		if err != nil {
			return b, err
		}
	}
	g := newIPAggregator(0)
	g.add(top, -1)
	g.addBlocked(blocked)
	g.finish(b, cfg, blocks)
	return b, nil
}

// ipHour returns the cached live board of a zone (re-queried at most
// once a minute; concurrent viewers share one set of queries).
func (s *Server) ipHour(ctx context.Context, z config.Zone) *IPBoard {
	s.ipMu.Lock()
	e := s.ipCache[z.ZoneID]
	if e == nil {
		e = &ipEntry{}
		s.ipCache[z.ZoneID] = e
	}
	s.ipMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	now := s.Now()
	ttl := ipLiveTTL
	if e.b != nil && e.b.Err != "" {
		ttl = ipErrTTL
	}
	if e.b != nil && now.Sub(e.b.At) < ttl {
		return e.b
	}
	to := now.Add(-liveLag).Truncate(time.Minute)
	qctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	evs, err := s.Archive.ActiveBlocks(z.ZoneID)
	if err != nil {
		return &IPBoard{Span: ipSpanHour, Err: err.Error(), At: now}
	}
	b, err := buildIPHour(qctx, s.Analytics, s.eff(), z, to.Add(-liveSpan), to, !s.noASN(ctx, z), ipBlocks(evs))
	if err != nil {
		b.Err = err.Error()
	}
	b.At = now
	e.b = b
	return b
}

func (s *Server) ipsPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	q := r.URL.Query()
	p := page{Title: s.L(r).t("nav_ips"), Zone: z, Nav: "ips", Refresh: s.Cfg.Console.RefreshSeconds}
	var b *IPBoard
	if q.Get("span") == ipSpanHour {
		if s.Analytics == nil {
			p.Err = s.L(r).t("ips_live_off")
			b = &IPBoard{Span: ipSpanHour}
		} else {
			b = s.ipHour(r.Context(), z)
		}
	} else {
		var err error
		if b, err = buildIPDay(s.Archive, s.eff(), z, q.Get("sort") == "count"); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	p.IPs = b
	s.render(w, r, http.StatusOK, "ips", p)
}
