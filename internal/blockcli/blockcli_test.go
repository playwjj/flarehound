package blockcli

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/block/fakecf"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/store"
)

type fakeRead struct{}

func (fakeRead) Count(_ context.Context, _ string, from, _ time.Time, f cfapi.Filter) (int64, error) {
	switch {
	case f.ASN == 24940:
		return 45_000, nil
	case f.ASN == 4134:
		return 300, nil
	case f.ClientIP != "":
		return 20, nil
	case from.Hour() == 8 && from.Day() == 17:
		return 150_000, nil // current hour
	}
	return 100_000, nil // yesterday
}
func (fakeRead) ASNName(_ context.Context, _ string, _, _ time.Time, asn int) (string, error) {
	return map[int]string{24940: "HETZNER-AS", 4134: "CHINANET-BACKBONE"}[asn], nil
}
func (fakeRead) Capabilities(context.Context, string) (cfapi.Caps, error) {
	return cfapi.Caps{FirewallEnabled: true, FirewallMaxAge: 72 * time.Hour}, nil
}

func (fakeRead) FirewallTop(_ context.Context, _ string, _, _ time.Time, _, _ string, _ int) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "AS24940", ASN: 24940, Count: 10}}, nil
}

var now = time.Date(2026, 11, 17, 9, 10, 0, 0, time.UTC)

func newEnv(t *testing.T, input string) (*Env, *fakecf.CF, *bytes.Buffer) {
	t.Helper()
	cfg := &config.Config{Location: time.UTC}
	cfg.Cloudflare.AccountID = strings.Repeat("a", 32)
	cfg.Schedule.IntradayInterval, cfg.Schedule.IntradayOffset = "1h", "7m"
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cf := fakecf.New("pro", 20)
	cf.Origins = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	out := &bytes.Buffer{}
	e := &Env{Cfg: cfg, Zone: config.Zone{ZoneID: "z", Name: "example.com"}, Read: fakeRead{}, Write: cf, Store: st,
		In: strings.NewReader(input), Out: out, Now: func() time.Time { return now }, Actor: "cli"}
	return e, cf, out
}

func target(t *testing.T, typ, v string) block.Target {
	tg, err := block.Parse(typ, v)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestBlockHostingASN(t *testing.T) {
	e, cf, out := newEnv(t, "y\n")
	err := e.Block(context.Background(), target(t, "asn", "24940"), BlockOpts{Action: block.Block, TTL: 24 * time.Hour, Reason: "crawler flood"})
	if err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"HETZNER-AS", "hosting network", "create rule flarehound-asn-block", "(ip.geoip.asnum in {24940}) and not cf.client.bot",
		"90.0% of the excess", "Expires:", "Apply? [y/N]", "verified by read-back"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if _, ok := cf.Rule("flarehound-asn-block"); !ok {
		t.Fatal("rule not created")
	}
	evs, _ := e.Store.ActiveBlocks("z")
	if len(evs) != 1 || evs[0].Reason != "crawler flood" || !evs[0].ExpiresAt.Equal(now.Add(24*time.Hour)) || evs[0].RuleID == "" {
		t.Fatalf("audit %+v", evs)
	}
}

func TestDeclineChangesNothing(t *testing.T) {
	e, cf, _ := newEnv(t, "n\n")
	if err := e.Block(context.Background(), target(t, "asn", "24940"), BlockOpts{}); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v", err)
	}
	if len(cf.RS.Rules) != 0 {
		t.Fatal("declined block changed Cloudflare")
	}
}

func TestEyeballBlockNeedsRetypedASN(t *testing.T) {
	e, cf, out := newEnv(t, "y\n")
	err := e.Block(context.Background(), target(t, "asn", "4134"), BlockOpts{Action: block.Block, Yes: true})
	if !errors.Is(err, ErrAborted) || len(cf.RS.Rules) != 0 {
		t.Fatalf("eyeball block went through with a plain yes: %v", err)
	}
	if !strings.Contains(out.String(), "real people browse") || !strings.Contains(out.String(), "will not resolve") {
		t.Errorf("warnings missing:\n%s", out.String())
	}
	e2, cf2, _ := newEnv(t, "AS4134\n")
	if err := e2.Block(context.Background(), target(t, "asn", "4134"), BlockOpts{Action: block.Block}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cf2.Rule("flarehound-asn-block"); !ok {
		t.Fatal("confirmed eyeball block not applied")
	}
}

func TestOriginIPRefused(t *testing.T) {
	e, cf, _ := newEnv(t, "y\n")
	err := e.Block(context.Background(), target(t, "ip", "93.184.216.0/24"), BlockOpts{Yes: true})
	if err == nil || !strings.Contains(err.Error(), "origin IP") || len(cf.Calls) != 0 {
		t.Fatalf("origin block not refused: %v %v", err, cf.Calls)
	}
	cf.FailDNS = true
	if err := e.Block(context.Background(), target(t, "ip", "45.13.7.9"), BlockOpts{Yes: true}); err == nil || !strings.Contains(err.Error(), "DNS: Read") {
		t.Fatalf("missing DNS permission must refuse: %v", err)
	}
	if err := e.Block(context.Background(), target(t, "ip", "45.13.7.9"), BlockOpts{Yes: true, SkipOriginCheck: true}); err != nil {
		t.Fatal(err)
	}
}

func TestTTLExpiry(t *testing.T) {
	e, cf, _ := newEnv(t, "")
	ctx := context.Background()
	if err := e.Block(ctx, target(t, "ua", "BadBot/1.0"), BlockOpts{Yes: true, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := e.Block(ctx, target(t, "asn", "24940"), BlockOpts{Yes: true}); err != nil { // permanent
		t.Fatal(err)
	}
	if n, err := e.Expire(ctx); err != nil || n != 0 {
		t.Fatalf("expired early: %d %v", n, err)
	}
	later := now.Add(2 * time.Hour)
	e.Now = func() time.Time { return later }
	e.Actor = "ttl"
	if n, err := e.Expire(ctx); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if _, ok := cf.Rule("flarehound-ua-block"); ok {
		t.Fatal("expired UA rule still present")
	}
	if _, ok := cf.Rule("flarehound-asn-challenge"); !ok {
		t.Fatal("permanent block was expired")
	}
	h, _ := e.Store.BlockHistory("z")
	last := h[len(h)-1]
	if last.Op != "expire" || last.Actor != "ttl" || last.Value != "BadBot/1.0" {
		t.Fatalf("audit %+v", last)
	}
}

func TestListShowsAttemptsAndDrift(t *testing.T) {
	e, cf, out := newEnv(t, "")
	ctx := context.Background()
	if err := e.Block(ctx, target(t, "asn", "24940"), BlockOpts{Yes: true, Reason: "flood"}); err != nil {
		t.Fatal(err)
	}
	// Someone deletes the rule by hand in the dashboard.
	if err := e.Block(ctx, target(t, "ua", "BadBot/1.0"), BlockOpts{Yes: true}); err != nil {
		t.Fatal(err)
	}
	r, _ := cf.Rule("flarehound-ua-block")
	_, _ = cf.DeleteRule(ctx, "z", "rs1", r.ID)
	out.Reset()
	if err := e.List(ctx, 7); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"AS24940", "challenge", "30", "flood", "MISSING in Cloudflare", "attempts cover only 3 day(s)"} {
		if !strings.Contains(s, want) {
			t.Errorf("list lacks %q:\n%s", want, s)
		}
	}
}
