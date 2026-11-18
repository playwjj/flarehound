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

// IPRow is one address, or one network of addresses summed: an IPv6
// /64 always (clients rotate inside one), an IPv4 /24 when two or more
// of its addresses are listed (a crawler or scraper farm walking a
// range would otherwise fill the board one address at a time).
type IPRow struct {
	Name     string   // address, or "66.249.66.0/24", "2001:db8:1:2::/64"
	Members  int      // addresses summed into a network (0: a single address)
	Top      []string // a network's largest addresses (up to ipTopMembers)
	ASN      int      // 0: unknown (plan without ASN, or not reported)
	Cat      string   // Cloudflare verified-bot category (bot rows only)
	Crawler  string   // crawler that crawls from this network, if any
	Known    bool     // the network is in the user's known faces
	Listed   bool     // inside an active FlareHound IP block
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
	Bots      []IPRow // folded: Cloudflare-verified bots
	BotSum    int64
	Hours     int       // archived hours with IP data in the window (24 h)
	Since     time.Time // oldest archived hour with IP data (zero: none yet)
	SortHours bool      // 24 h ranked by persistence (else by requests)
	Err       string
	At        time.Time
}

const ipTopMembers = 3

type ipEntry struct {
	mu sync.Mutex
	b  *IPBoard
}

// ipAddr is one listed address, summed over the window.
type ipAddr struct {
	name           string
	asn            int
	cat            string
	count, blocked int64
	strip          []bool
}

// ipGroupKey is the network an address is summed into: its IPv6 /64, or
// its IPv4 /24 (used only when the /24 has two or more addresses).
func ipGroupKey(s string) (key string, v6, ok bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s, false, false
	}
	a = a.Unmap()
	bits := 24
	if !a.Is4() {
		bits, v6 = 64, true
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return s, false, false
	}
	return p.String(), v6, true
}

// ipAggregator sums top lists (one per hour, or the live one) per
// address; finish groups them into networks.
type ipAggregator struct {
	by    map[string]*ipAddr
	hours int // slots in the strip (0: no strip)
}

func newIPAggregator(hours int) *ipAggregator {
	return &ipAggregator{by: map[string]*ipAddr{}, hours: hours}
}

func (g *ipAggregator) get(name string) *ipAddr {
	if a, err := netip.ParseAddr(name); err == nil {
		name = a.Unmap().String()
	}
	a := g.by[name]
	if a == nil {
		a = &ipAddr{name: name}
		if g.hours > 0 {
			a.strip = make([]bool, g.hours)
		}
		g.by[name] = a
	}
	return a
}

// add sums one top list; slot is the hour's strip index (-1: none).
func (g *ipAggregator) add(top []cfapi.Face, slot int) {
	for _, f := range top {
		a := g.get(f.Name)
		a.count += f.Count
		if a.asn == 0 {
			a.asn = f.ASN
		}
		if a.cat == "" {
			a.cat = f.Cat
		}
		if slot >= 0 && slot < len(a.strip) {
			a.strip[slot] = true
		}
	}
}

// addBlocked sums one top list of edge-stopped requests into addresses
// that are listed (an address only blocked, never in the top of all
// requests, is not on the board: its requests are handled already).
func (g *ipAggregator) addBlocked(top []cfapi.Face) {
	for _, f := range top {
		name := f.Name
		if a, err := netip.ParseAddr(name); err == nil {
			name = a.Unmap().String()
		}
		if a := g.by[name]; a != nil {
			a.blocked += f.Count
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

// group sums addresses into rows: IPv6 per /64, IPv4 per /24 when two
// or more of its addresses are listed, else the address alone.
func group(addrs []*ipAddr, hours int) []IPRow {
	nets := map[string][]*ipAddr{}
	v6 := map[string]bool{}
	var order []string
	for _, a := range addrs {
		k, is6, ok := ipGroupKey(a.name)
		if !ok {
			k = a.name
		}
		if _, seen := nets[k]; !seen {
			order = append(order, k)
		}
		nets[k] = append(nets[k], a)
		v6[k] = is6
	}
	var rows []IPRow
	for _, k := range order {
		as := nets[k]
		sort.SliceStable(as, func(i, j int) bool { return as[i].count > as[j].count })
		if len(as) == 1 && !v6[k] {
			a := as[0]
			rows = append(rows, IPRow{Name: a.name, ASN: a.asn, Cat: a.cat, Count: a.count, Blocked: a.blocked, Strip: a.strip,
				Drill: strings.Count(a.name, "/") == 0})
			continue
		}
		r := IPRow{Name: k, Members: len(as)}
		if hours > 0 {
			r.Strip = make([]bool, hours)
		}
		for _, a := range as {
			r.Count += a.count
			r.Blocked += a.blocked
			if r.ASN == 0 {
				r.ASN = a.asn
			}
			if r.Cat == "" {
				r.Cat = a.cat
			}
			for i, on := range a.strip {
				r.Strip[i] = r.Strip[i] || on
			}
			if len(r.Top) < ipTopMembers {
				r.Top = append(r.Top, a.name)
			}
		}
		rows = append(rows, r)
	}
	return rows
}

// finish turns the sums into the board's rows: verified bots and known
// networks folded, the rest ranked.
func (g *ipAggregator) finish(b *IPBoard, cfg *config.Config, blocks []netip.Prefix) {
	var people, bots []*ipAddr
	for _, a := range g.by {
		if a.cat != "" {
			bots = append(bots, a)
		} else {
			people = append(people, a)
		}
	}
	// Map order is random: sort for a stable grouping and Top list.
	for _, as := range [][]*ipAddr{people, bots} {
		sort.Slice(as, func(i, j int) bool { return as[i].name < as[j].name })
	}
	fill := func(rows []IPRow) []IPRow {
		for i := range rows {
			r := &rows[i]
			for _, on := range r.Strip {
				if on {
					r.Hours++
				}
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
		return rows
	}
	for _, r := range fill(group(people, g.hours)) {
		switch {
		case r.Known:
			b.Known = append(b.Known, r)
			b.KnownSum += r.Count
		case len(b.Rows) < ipShown:
			b.Rows = append(b.Rows, r)
		}
	}
	for _, r := range fill(group(bots, g.hours)) {
		b.Bots = append(b.Bots, r)
		b.BotSum += r.Count
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
		if h.TopIPs == nil && h.BotIPs == nil { // before v1.14, or the query failed
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
		g.add(h.BotIPs, slot)
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
func buildIPHour(ctx context.Context, an Analytics, cfg *config.Config, z config.Zone, from, to time.Time, dim string, blocks []netip.Prefix) (*IPBoard, error) {
	b := &IPBoard{Span: ipSpanHour, From: from, To: to}
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
	run(1, func() (err error) { top, err = an.Top(ctx, z.ZoneID, from, to, dim, 2*ipLimit, cfapi.Filter{}); return })
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
	others, bots := cfapi.SplitBots(top, ipLimit)
	g.add(others, -1)
	g.add(bots, -1)
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
	b, err := buildIPHour(qctx, s.Analytics, s.eff(), z, to.Add(-liveSpan), to, s.ipDim(ctx, z), ipBlocks(evs))
	if err != nil {
		b.Err = err.Error()
	}
	b.At = now
	e.b = b
	return b
}

// ipDim is the client-IP grouping for the zone's plan (all of it when
// the plan has not been probed).
func (s *Server) ipDim(ctx context.Context, z config.Zone) string {
	if s.Caps == nil {
		return cfapi.AllCaps().ClientIPDim()
	}
	return s.Caps(ctx, z).ClientIPDim()
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
