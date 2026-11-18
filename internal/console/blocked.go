package console

// The blocked board (movers page): who is knocking on the firewall in
// the movers' window — sources ranked by the requests the edge already
// stopped: edge 403 with no origin response (a rule's block and a
// failed challenge both answer 403; a 403 the origin itself returned
// went through, so it is excluded).
// The archive keeps only Top lists without a status split, so these
// are live queries like the drill-down's, cached per window.
//
// Blocked traffic costs no Worker calls and no origin traffic, so a
// riser here is never an incident by itself. The board exists so a
// rise in the zone totals can be attributed at a glance — "old faces
// knocking", not a breach — without leaving the console.

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

const (
	blockedTTL    = 10 * time.Minute
	blockedErrTTL = time.Minute // a failure is retried after this, not on every refresh
	blockedLimit  = 8
)

// ShareRow is one face with its share of a total: a knocking source
// on the blocked board, a loud face in the live hour.
type ShareRow struct {
	Name  string
	Count int64
	Share float64 // percent of the list's total (all blocked requests, all requests)
}

// Blocked is the board for one window.
type Blocked struct {
	Window store.Window
	Total  int64 // all edge-403 requests in the window
	ASNs   []ShareRow
	UAs    []ShareRow
	Err    string
	At     time.Time
}

type blockedEntry struct {
	mu sync.Mutex
	b  *Blocked
}

func shareRows(faces []cfapi.Face, total int64) []ShareRow {
	out := make([]ShareRow, 0, len(faces))
	for _, f := range faces {
		r := ShareRow{Name: f.Name, Count: f.Count}
		if total > 0 {
			r.Share = float64(f.Count) / float64(total) * 100
		}
		out = append(out, r)
	}
	return out
}

// buildBlocked queries the window's blocked sources. hasASN=false
// skips the ASN list on plans whose analytics have no ASN dimension.
func buildBlocked(ctx context.Context, an Analytics, zone config.Zone, w store.Window, hasASN bool) *Blocked {
	b := &Blocked{Window: w}
	f := cfapi.EdgeBlocked()
	var (
		wg        sync.WaitGroup
		asns, uas []cfapi.Face
		errs      = make([]error, 3)
	)
	run := func(i int, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fn()
		}()
	}
	run(0, func() error {
		n, err := an.Count(ctx, zone.ZoneID, w.From, w.To, f)
		b.Total = n
		return err
	})
	if hasASN {
		run(1, func() error {
			fs, err := an.Top(ctx, zone.ZoneID, w.From, w.To, cfapi.DimASN, blockedLimit, f)
			asns = fs
			return err
		})
	}
	run(2, func() error {
		fs, err := an.Top(ctx, zone.ZoneID, w.From, w.To, cfapi.DimUserAgent, blockedLimit, f)
		uas = fs
		return err
	})
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			b.Err = err.Error()
			return b
		}
	}
	b.ASNs = shareRows(asns, b.Total)
	b.UAs = shareRows(uas, b.Total)
	return b
}

// blocked returns the cached board for the window (concurrent viewers
// share one set of queries), mirroring the drill-down's cache.
func (s *Server) blocked(ctx context.Context, z config.Zone, w store.Window, hasASN bool) *Blocked {
	key := z.ZoneID + "|" + strconv.FormatInt(w.From.Unix(), 10)
	s.blockedMu.Lock()
	e := s.blockedCache[key]
	if e == nil {
		if len(s.blockedCache) > 200 {
			for k, v := range s.blockedCache {
				if v.b != nil && s.Now().Sub(v.b.At) > blockedTTL {
					delete(s.blockedCache, k)
				}
			}
		}
		e = &blockedEntry{}
		s.blockedCache[key] = e
	}
	s.blockedMu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	// The board sits on an auto-refreshing page: a failure is cached
	// briefly so a Cloudflare outage does not stall every refresh on
	// fresh queries.
	ttl := blockedTTL
	if e.b != nil && e.b.Err != "" {
		ttl = blockedErrTTL
	}
	if e.b != nil && s.Now().Sub(e.b.At) < ttl {
		return e.b
	}
	qctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	b := buildBlocked(qctx, s.Analytics, z, w, hasASN)
	b.At = s.Now()
	e.b = b
	return b
}
