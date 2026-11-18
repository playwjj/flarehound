package console

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

// knockAnalytics answers only edge-403 queries, with distinctive data.
type knockAnalytics struct {
	err   error
	calls int
}

func (k *knockAnalytics) Count(_ context.Context, _ string, _, _ time.Time, fl cfapi.Filter) (int64, error) {
	k.calls++
	if k.err != nil {
		return 0, k.err
	}
	if fl != cfapi.EdgeBlocked() {
		return 0, errors.New("blocked board must filter on edge 403 without origin response")
	}
	return 1000, nil
}

func (k *knockAnalytics) Top(_ context.Context, _ string, _, _ time.Time, dim string, _ int, fl cfapi.Filter) ([]cfapi.Face, error) {
	if k.err != nil {
		return nil, k.err
	}
	if fl != cfapi.EdgeBlocked() {
		return nil, errors.New("blocked board must filter on edge 403 without origin response")
	}
	switch dim {
	case cfapi.DimASN:
		return []cfapi.Face{{Name: "AS45102", ASN: 45102, Count: 600}, {Name: "AS207990", ASN: 207990, Count: 100}}, nil
	case cfapi.DimUserAgent:
		return []cfapi.Face{{Name: "Knocker/9.9", Count: 700}}, nil
	}
	return nil, nil
}

func TestBuildBlocked(t *testing.T) {
	zone := config.Zone{Name: "example.com", ZoneID: "z1"}
	w := store.Window{From: time.Date(2026, 11, 18, 13, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 18, 14, 0, 0, 0, time.UTC)}

	b := buildBlocked(context.Background(), &knockAnalytics{}, zone, w, true)
	if b.Err != "" {
		t.Fatalf("buildBlocked: %s", b.Err)
	}
	if b.Total != 1000 || len(b.ASNs) != 2 || len(b.UAs) != 1 {
		t.Fatalf("board = %+v", b)
	}
	if b.ASNs[0].Name != "AS45102" || b.ASNs[0].Share != 60 {
		t.Fatalf("top ASN row = %+v", b.ASNs[0])
	}
	if b.UAs[0].Name != "Knocker/9.9" || b.UAs[0].Share != 70 {
		t.Fatalf("top UA row = %+v", b.UAs[0])
	}

	// Without the ASN dimension the ASN list is skipped, not an error.
	b = buildBlocked(context.Background(), &knockAnalytics{}, zone, w, false)
	if b.Err != "" || len(b.ASNs) != 0 || len(b.UAs) != 1 {
		t.Fatalf("no-ASN board = %+v", b)
	}

	// A failed query surfaces as Err (the page then hides the board).
	b = buildBlocked(context.Background(), &knockAnalytics{err: errors.New("boom")}, zone, w, true)
	if b.Err == "" {
		t.Fatal("query failure must set Err")
	}
}

func TestBlockedBoardOnMoversPage(t *testing.T) {
	e := newWriteEnv(t, false)
	e.srv.Analytics = &knockAnalytics{}
	_, body, _ := e.admin.do("GET", "/movers?dim=ua", nil, nil)
	for _, want := range []string{"Stopped at the edge", "Knocker/9.9", "AS45102", "1,000 stopped in this hour", "/movers/drill?z=example.com&amp;dim=asn&amp;name=AS45102"} {
		if !strings.Contains(body, want) {
			t.Fatalf("movers page lacks blocked-board %q:\n%s", want, body)
		}
	}
}

// A failed board is cached briefly: an auto-refreshing movers page must
// not re-run three live queries on every refresh while Cloudflare fails.
func TestBlockedErrorBackoff(t *testing.T) {
	e := newWriteEnv(t, false)
	k := &knockAnalytics{err: errors.New("boom")}
	e.srv.Analytics = k
	now := time.Date(2026, 11, 18, 22, 40, 0, 0, time.UTC)
	e.srv.Now = func() time.Time { return now }
	zone := config.Zone{Name: "example.com", ZoneID: "z1"}
	w := store.Window{From: now.Truncate(time.Hour).Add(-time.Hour), To: now.Truncate(time.Hour)}
	e.srv.blocked(context.Background(), zone, w, true)
	e.srv.blocked(context.Background(), zone, w, true)
	if k.calls != 1 {
		t.Fatalf("failed board re-queried within the backoff: %d count calls", k.calls)
	}
	now = now.Add(blockedErrTTL)
	k.err = nil
	if b := e.srv.blocked(context.Background(), zone, w, true); b.Err != "" || k.calls != 2 {
		t.Fatalf("board not retried after the backoff: err=%q calls=%d", b.Err, k.calls)
	}
}
