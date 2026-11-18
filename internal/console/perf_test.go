package console

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
)

// slowAnalytics answers after a delay, like Cloudflare over a slow link.
type slowAnalytics struct{ fakeAnalytics }

func (s *slowAnalytics) Count(ctx context.Context, z string, f, t time.Time, fl cfapi.Filter) (int64, error) {
	time.Sleep(60 * time.Millisecond)
	return s.fakeAnalytics.Count(ctx, z, f, t, fl)
}
func (s *slowAnalytics) Top(ctx context.Context, z string, f, t time.Time, d string, l int, fl cfapi.Filter) ([]cfapi.Face, error) {
	time.Sleep(60 * time.Millisecond)
	return s.fakeAnalytics.Top(ctx, z, f, t, d, l, fl)
}

func TestDrillIsConcurrent(t *testing.T) {
	an := &slowAnalytics{}
	start := time.Now()
	d := buildDrill(context.Background(), an, config.Zone{ZoneID: zoneID}, DimUA, "Crawler/1.0", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	took := time.Since(start)
	if d.Err != "" || len(d.Sections) != 4 || d.Cur != 14000 {
		t.Fatalf("drill: %+v", d)
	}
	// 10 queries × 60 ms = 600 ms in sequence; 4 at a time ≈ 180 ms.
	if took > 400*time.Millisecond {
		t.Fatalf("drill-down queries ran in sequence: %s", took)
	}
	if an.n.Load() != 10 {
		t.Fatalf("queries: %d", an.n.Load())
	}
}

func TestRulesCacheAndWarm(t *testing.T) {
	e, fr := rulesEnv(t, true)
	c := e.admin
	audits := 0
	e.srv.Auditor = func(_ context.Context, z config.Zone) (report.AuditData, error) {
		audits++
		return report.AuditData{Zone: z.Name, NA: "test"}, nil
	}
	e.srv.warmPages(context.Background())
	if fr.reads != 2 || audits != 1 {
		t.Fatalf("warm: %d rule reads, %d audits", fr.reads, audits)
	}
	reads := fr.reads
	c.do("GET", "/rules", nil, nil)
	c.do("GET", "/rules?phase=ratelimit", nil, nil)
	if fr.reads != reads {
		t.Fatalf("warm cache not used: %d extra reads", fr.reads-reads)
	}
	if _, body, _ := c.do("GET", "/audit", nil, nil); audits != 1 || !strings.Contains(body, "test") {
		t.Fatalf("audit page re-ran the warm audit: %d", audits)
	}
	c.do("GET", "/rules?fresh=1", nil, nil)
	if fr.reads != reads+1 {
		t.Fatal("refresh did not read the rules again")
	}
	// A change forgets the cache (rules and audit).
	_, apply := reviewRule(t, c, url.Values{"op": {"disable"}, "sel": {"r2"}, "phase": {"custom"}})
	if code, _, _ := c.do("POST", "/rules/apply", apply, nil); code != http.StatusSeeOther {
		t.Fatalf("apply: %d", code)
	}
	reads = fr.reads
	if _, body, _ := c.do("GET", "/rules", nil, nil); fr.reads != reads+1 || !strings.Contains(body, "Disabled") && !strings.Contains(body, "disabled") {
		t.Fatalf("rules page served stale rules after a change (reads %d → %d)", reads, fr.reads)
	}
	c.do("GET", "/audit", nil, nil)
	if audits != 2 {
		t.Fatalf("audit not re-run after a rule change: %d", audits)
	}
}

func TestPlanAwareness(t *testing.T) {
	e, fr := rulesEnv(t, true)
	c := e.admin
	// No ASN dimension (Free): say why the ASN lists are empty.
	e.srv.Caps = func(context.Context, config.Zone) cfapi.Caps {
		return cfapi.Caps{Probed: true, HTTPFields: map[string]bool{cfapi.DimUserAgent: true}}
	}
	if _, body, _ := c.do("GET", "/movers?dim=asn", nil, nil); !strings.Contains(body, "no ASN dimension") {
		t.Fatal("movers ASN tab does not explain the missing dimension")
	}
	if _, body, _ := c.do("GET", "/movers?dim=ua", nil, nil); strings.Contains(body, "no ASN dimension") {
		t.Fatal("ASN note shown on the UA tab")
	}
	if _, body, _ := c.do("GET", "/faces", nil, nil); !strings.Contains(body, "no ASN dimension") {
		t.Fatal("faces page does not explain the missing ASN dimension")
	}

	// Free plan: paid skip scopes hidden, rate-limit timing fixed.
	fr.plan = "free"
	e.srv.forgetRules(e.srv.Cfg.Cloudflare.Zones[0])
	_, body, _ := c.do("GET", "/rules/recipe/allow-verified-bots", nil, nil)
	if strings.Contains(body, "bots</option>") || !strings.Contains(body, "Free plan") {
		t.Fatalf("Free plan form offers Super Bot Fight Mode:\n%s", body)
	}
	_, body, _ = c.do("GET", "/rules/recipe/ratelimit-paths", nil, nil)
	if !strings.Contains(body, `name="in_period" value="10" readonly`) {
		t.Fatal("Free plan rate-limit period not fixed")
	}

	// Quota full: said up front, no form.
	fr.mu.Lock()
	fr.rules[cfapi.PhaseRateLimit] = []map[string]any{{"id": "rl1", "action": "block", "expression": `http.request.uri.path eq "/x"`, "description": "rl", "enabled": true}}
	fr.mu.Unlock()
	e.srv.forgetRules(e.srv.Cfg.Cloudflare.Zones[0])
	_, body, _ = c.do("GET", "/rules/recipes", nil, nil)
	if !strings.Contains(body, "at its plan limit (1 of 1)") {
		t.Fatal("recipe catalogue does not warn about the full rate-limit quota")
	}
	_, body, _ = c.do("GET", "/rules/recipe/ratelimit-paths", nil, nil)
	if !strings.Contains(body, "at its plan limit") || strings.Contains(body, `action="/rules/review"`) {
		t.Fatal("full quota: form still offered")
	}
}

func TestPrune(t *testing.T) {
	db := testDB(t)
	u, _ := db.CreateUser("alice", "", "alice-password", RoleAdmin, false)
	_, dead, _ := db.CreateSnapshot(u.ID, "alice", "old", zoneID, "<html>old</html>", time.Hour)
	_, live, _ := db.CreateSnapshot(u.ID, "alice", "new", zoneID, "<html>new</html>", 500*24*time.Hour)
	_ = db.Audit("alice", "ip", "login", "", "")
	_ = db.PutEffect(zoneID, 1, []byte(`{}`))
	db.now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }
	ps, err := db.Prune()
	if err != nil {
		t.Fatal(err)
	}
	if ps.Snapshots != 1 || ps.Audit != 1 || ps.Effects != 1 {
		t.Fatalf("prune: %+v", ps)
	}
	if sn, _, _ := db.SnapshotByID(dead); !sn.Pruned() || sn.Title != "old" {
		t.Fatalf("dead snapshot: %+v", sn)
	}
	if sn, _, _ := db.SnapshotByID(live); sn.Pruned() {
		t.Fatal("a snapshot with a live link lost its page")
	}
}
