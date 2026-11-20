package console

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/sim"
)

// simLive is fakeLive that can also simulate: a Pro zone where AS24940
// sends 45,000 requests, 30,000 of them verified bots.
type simLive struct {
	fakeLive
	free bool
}

func (f simLive) Capabilities(context.Context, string) (cfapi.Caps, error) {
	fields := map[string]bool{"dimensions_clientIP": true, "dimensions_userAgent": true, "dimensions_clientRequestPath": true, "dimensions_verifiedBotCategory": true}
	if !f.free {
		fields["dimensions_clientAsn"] = true
	}
	return cfapi.Caps{Probed: true, HTTPFields: fields, FirewallEnabled: !f.free, FirewallMaxAge: 30 * 24 * time.Hour}, nil
}

func (f simLive) Count(ctx context.Context, z string, from, to time.Time, fl cfapi.Filter) (int64, error) {
	if fl.Where == "" || !strings.Contains(fl.Where, "24940") {
		return f.fakeLive.Count(ctx, z, from, to, fl)
	}
	switch {
	case strings.Contains(fl.Where, `verifiedBotCategory_neq:""`):
		return 30_000, nil
	case strings.Contains(fl.Where, `verifiedBotCategory:""`):
		return 15_000, nil
	}
	return 45_000, nil
}

func (f simLive) Top(ctx context.Context, z string, from, to time.Time, dim string, n int, fl cfapi.Filter) ([]cfapi.Face, error) {
	if fl.Where == "" {
		return f.fakeLive.Top(ctx, z, from, to, dim, n, fl)
	}
	switch dim {
	case cfapi.DimUserAgent:
		return []cfapi.Face{{Name: "Scraper/2.0", Count: 15_000}}, nil
	case cfapi.DimPath:
		return []cfapi.Face{{Name: "/search", Count: 12_000}}, nil
	}
	return nil, nil
}

func (simLive) Hourly(context.Context, string, time.Time, time.Time, cfapi.Filter) (map[time.Time]int64, error) {
	return map[time.Time]int64{}, nil
}

func (simLive) FirewallGroups(context.Context, string, time.Time, time.Time, string, int, cfapi.Filter) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "managed_challenge r9", Count: 1_000}}, nil
}

func TestSimulatePage(t *testing.T) {
	e := newWriteEnv(t, false)
	e.srv.Analytics = simLive{}
	c := e.admin
	if code, body, _ := c.do("GET", "/simulate", nil, nil); code != http.StatusOK || !strings.Contains(body, `name="expr"`) {
		t.Fatalf("form: %d", code)
	}
	q := url.Values{"expr": {"(ip.geoip.asnum eq 24940 and not cf.client.bot)"}, "action": {"challenge"}}
	code, body, _ := c.do("GET", "/simulate?"+q.Encode(), nil, nil)
	if code != http.StatusOK {
		t.Fatalf("simulate: %d", code)
	}
	for _, want := range []string{"Gross 45,000", "verified bots 30,000", "net new ≈ 14,000", "/search", "Scraper/2.0", "approximate (includes a cross-dataset estimate)"} {
		if !strings.Contains(body, want) {
			t.Errorf("simulate page lacks %q", want)
		}
	}
	// Not evaluable: named, no numbers.
	q.Set("expr", `http.cookie contains "x"`)
	_, body, _ = c.do("GET", "/simulate?"+q.Encode(), nil, nil)
	if !strings.Contains(body, "Cannot be evaluated") || !strings.Contains(body, "http.cookie") {
		t.Fatalf("unevaluable not named:\n%s", body)
	}
	// A parse error is shown, not a 500.
	q.Set("expr", `(ip.src eq`)
	if code, body, _ := c.do("GET", "/simulate?"+q.Encode(), nil, nil); code != http.StatusOK || !strings.Contains(body, "does not parse") {
		t.Fatalf("parse error: %d", code)
	}
}

func TestSimulateFreeZone(t *testing.T) {
	e := newWriteEnv(t, false)
	e.srv.Analytics = simLive{free: true}
	q := url.Values{"expr": {"ip.geoip.asnum eq 45102"}}
	_, body, _ := e.admin.do("GET", "/simulate?"+q.Encode(), nil, nil)
	if !strings.Contains(body, "no ASN dimension") || strings.Contains(body, "Gross") {
		t.Fatalf("free zone:\n%s", body)
	}
}

func TestBlockReviewSimulates(t *testing.T) {
	e := newWriteEnv(t, true)
	e.srv.Live = simLive{}
	form := url.Values{"type": {"asn"}, "value": {"24940"}, "action": {"challenge"}, "for": {"24h"}, "reason": {"sim"}}
	body, csrf, tok := e.review(t, e.admin, clone(form))
	if !strings.Contains(body, "Simulated (last 7 days)") || !strings.Contains(body, "net new ≈ 14,000") {
		t.Fatalf("review lacks the simulation:\n%s", body)
	}
	if !strings.Contains(body, "position #") {
		t.Fatalf("review simulation does not say where the rule sits:\n%s", body)
	}
	if strings.Contains(body, ">Measured<") {
		t.Fatal("the single-target measurement is still shown next to the simulation")
	}
	ok := clone(form)
	ok.Set("csrf", csrf)
	ok.Set("review", tok)
	if code, _, _ := e.admin.do("POST", "/blocks/apply", ok, nil); code != http.StatusSeeOther {
		t.Fatalf("apply: %d", code)
	}
	act, _ := e.st.ActiveBlocks(zoneID)
	var id int64
	for _, a := range act {
		if a.Value == "24940" {
			id = a.ID
		}
	}
	raw, found, err := e.st.BlockSim(id)
	if err != nil || !found {
		t.Fatalf("no simulation kept with block %d: %v", id, err)
	}
	r, err := sim.Decode(raw)
	if err != nil || r.Net != 14_000 || r.Expr != "(ip.geoip.asnum in {24940}) and not cf.client.bot" {
		t.Fatalf("snapshot: %+v %v", r, err)
	}
	// The before/after page sets the prediction against the attempts.
	var eff Effect
	e.srv.predict(&eff, id)
	if !eff.PredictedKnown || !strings.Contains(eff.PredictionLine("en"), "predicted net new ≈ 83/h") {
		t.Fatalf("prediction: %+v %q", eff, eff.PredictionLine("en"))
	}
}

// IP blocks keep the light measurement; a read API that cannot simulate
// leaves the review as it was.
func TestBlockReviewWithoutSim(t *testing.T) {
	e := newWriteEnv(t, true)
	form := url.Values{"type": {"asn"}, "value": {"24940"}, "action": {"block"}}
	body, _, _ := e.review(t, e.admin, clone(form))
	if strings.Contains(body, "Simulated") || !strings.Contains(body, "45000 requests") {
		t.Fatalf("fallback review:\n%s", body)
	}
}

// Known faces added in the console's settings (the overlay) reach the
// simulator without a restart.
func TestSimulateKnownFromOverlay(t *testing.T) {
	e := newWriteEnv(t, false)
	e.srv.Analytics = simLive{}
	q := url.Values{"expr": {"(ip.geoip.asnum eq 24940 and not cf.client.bot)"}}
	_, body, _ := e.admin.do("GET", "/simulate?"+q.Encode(), nil, nil)
	if strings.Contains(body, "known source") {
		t.Fatal("known source flagged before it was registered")
	}
	eff := *e.srv.Cfg
	eff.KnownFaces.UserAgents = []string{"scraper"}
	e.srv.effMu.Lock()
	e.srv.effCfg = &eff
	e.srv.effMu.Unlock()
	q.Set("days", "1") // a different window: not the cached report
	_, body, _ = e.admin.do("GET", "/simulate?"+q.Encode(), nil, nil)
	if !strings.Contains(body, "it hits the known source scraper") {
		t.Fatalf("overlay known face not used:\n%s", body)
	}
}
